package roles

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RebootTimeout is how long a rebooted host has to come back.
const RebootTimeout = 10 * time.Minute

// Runner runs a script as root on a host and returns its output.
type Runner interface {
	Run(ctx context.Context, script string) ([]byte, error)
}

// Target is a host a role runs on. Connect opens the connection and reports
// the operating system, which decides how steps run. Prepare, when set,
// compiles the role for this host, for roles with variables.
type Target struct {
	ID      string
	Name    string
	Connect func(ctx context.Context) (Runner, Host, error)
	Prepare func(Host) (Role, error)
}

// StepResult is one step's outcome on one host.
type StepResult struct {
	Step   int    `json:"step"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok, changed, skipped, reboot, failed, not run
	Detail string `json:"detail,omitempty"`
}

// HostResult is a role's outcome on one host.
type HostResult struct {
	InstanceID string       `json:"instanceID"`
	Instance   string       `json:"instance"`
	Status     string       `json:"status"` // ok, changed, failed, skipped
	Error      string       `json:"error,omitempty"`
	Steps      []StepResult `json:"steps"`
}

// Run is the result of a plan or an apply.
type Run struct {
	Kind    string       `json:"kind"` // plan or apply
	RoleID  string       `json:"roleID"`
	Version int          `json:"version"`
	Hash    string       `json:"hash"`
	Hosts   []HostResult `json:"hosts"`
	Changes int          `json:"changes"`
	Failed  int          `json:"failed"`
	Risks   []string     `json:"risks,omitempty"`
}

// Add records a host's result in the run's totals.
func (r *Run) Add(h HostResult) {
	r.Hosts = append(r.Hosts, h)
	r.Changes += h.Changed()
	if h.Status == "failed" {
		r.Failed++
	}
}

// Changed counts the steps that changed, or would change, the host.
func (h HostResult) Changed() int {
	n := 0
	for _, s := range h.Steps {
		if s.Status == StatusChanged || s.Status == StatusReboot {
			n++
		}
	}
	return n
}

// RunHosts runs the role on each target, up to parallel targets at a time,
// and returns the results in target order.
func RunHosts(ctx context.Context, r Role, targets []Target, apply bool, parallel int) []HostResult {
	results := make([]HostResult, len(targets))
	sem := make(chan struct{}, max(parallel, 1))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = RunHost(ctx, r, t, apply)
		}()
	}
	wg.Wait()
	return results
}

// RunHost runs every step in order and stops at the first failure. With
// apply false, steps only report what they would change.
func RunHost(ctx context.Context, r Role, t Target, apply bool) HostResult {
	res := HostResult{InstanceID: t.ID, Instance: t.Name, Status: "ok"}
	if r.AWS() != nil || r.AWSNetwork() != nil {
		res.Status, res.Error = "failed", "AWS provisioning requires a Korta Enterprise manager; use korta roles create, plan and apply"
		return res
	}
	run, host, err := t.Connect(ctx)
	if err == nil && t.Prepare != nil {
		r, err = t.Prepare(host)
	}
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	if r.AWS() != nil {
		res.Status, res.Error = "failed", "AWS provisioning requires a Korta Enterprise manager"
		return res
	}
	host.Planned = map[string]bool{}
	changed := false
	for i, s := range r.Steps {
		sr := StepResult{Step: i + 1, Name: StepName(s)}
		if res.Status == "failed" {
			sr.Status = "not run"
			res.Steps = append(res.Steps, sr)
			continue
		}
		script, err := Script(r.Name, s, host, apply, changed)
		var out []byte
		if err == nil {
			out, err = run.Run(ctx, script)
		}
		status, detail, ok := ParseResult(out)
		switch {
		case err != nil:
			// Lead with the step's own last message, such as why a check
			// failed, rather than the bare exit status.
			sr.Status, sr.Detail = "failed", err.Error()
			if last := lastLine(string(out)); last != "" && !strings.Contains(err.Error(), "SSH connection") {
				sr.Detail = last + "\n" + err.Error()
			}
		case !ok:
			sr.Status, sr.Detail = "failed", "the step did not report a result"
		default:
			sr.Status, sr.Detail = status, detail
		}
		if sr.Status == "failed" {
			res.Status, res.Error = "failed", fmt.Sprintf("step %d (%s): %s", i+1, sr.Name, firstLine(sr.Detail))
		}
		if sr.Status == StatusChanged || sr.Status == StatusReboot {
			changed = true
			for _, c := range s.Provides() {
				host.Planned[c] = !apply
			}
			if res.Status == "ok" {
				res.Status = "changed"
			}
		}
		if sr.Status == StatusReboot {
			if err := WaitForHost(ctx, run); err != nil {
				sr.Status, sr.Detail = "failed", sr.Detail+"; "+err.Error()
				res.Status, res.Error = "failed", fmt.Sprintf("step %d (%s): %v", i+1, sr.Name, err)
			} else {
				sr.Detail += "; back online"
			}
		}
		res.Steps = append(res.Steps, sr)
	}
	return res
}

// WaitForHost waits for a rebooting host to accept commands again.
func WaitForHost(ctx context.Context, run Runner) error {
	deadline := time.Now().Add(RebootTimeout)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(15 * time.Second):
	}
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err := run.Run(c, "true")
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("host did not come back within %s after rebooting", RebootTimeout)
}

// StepName is the step's name, or a description when it has none.
func StepName(s Step) string {
	if s.Name != "" {
		return s.Name
	}
	switch s.Type {
	case "scheduled-job":
		return "scheduled job " + s.Job
	case "ntp":
		return "network time synchronization"
	case "dns":
		return "DNS nameservers " + strings.Join(s.Nameservers, ", ")
	case "hostname":
		return "hostname " + s.Hostname
	case "timezone":
		return "timezone " + s.Timezone
	case "packages":
		return fmt.Sprintf("packages %s %v", s.State, s.Packages)
	case "patch":
		return fmt.Sprintf("patch %s (reboot %s)", s.Scope, s.Reboot)
	case "file":
		return "file " + s.Path
	case "service":
		return "service " + s.Service
	case "user":
		return "user " + s.User
	case "group":
		return "group " + s.Group
	case "directory":
		return "directory " + s.Path
	case "firewall":
		return fmt.Sprintf("firewall %s %d/%s", s.State, s.Port, s.Protocol)
	}
	return s.Type
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
