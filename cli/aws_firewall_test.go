package cli

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexusrun/korta/roles"
)

type firewallRunner struct {
	scripts []string
	state   string
	failAt  int
}

func (f *firewallRunner) Run(_ context.Context, script string) ([]byte, error) {
	f.scripts = append(f.scripts, script)
	if f.failAt == len(f.scripts) {
		return nil, errors.New("connection failed")
	}
	if len(f.scripts) == 1 {
		return []byte(f.state), nil
	}
	return nil, nil
}
func TestAWSFirewallActivation(t *testing.T) {
	peer := netip.MustParseAddr("203.0.113.5")
	role := roles.Role{Steps: []roles.Step{{Type: "firewall", State: "open", Port: 80, Protocol: "tcp", Sources: []string{"0.0.0.0/0", "::/0"}}}}
	for _, tc := range []struct {
		name, state      string
		fail             int
		changed, wantErr bool
		calls            int
	}{
		{"inactive", "inactive", 0, true, false, 4},
		{"already active", "active", 0, false, false, 1},
		{"activation fails", "inactive", 2, false, true, 2},
		{"verification fails", "inactive", 3, false, true, 3},
		{"cancellation fails", "inactive", 4, false, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &firewallRunner{state: tc.state, failAt: tc.fail}
			changed, err := enableAWSFirewall(context.Background(), f, peer, role)
			if changed != tc.changed || (err != nil) != tc.wantErr || len(f.scripts) != tc.calls {
				t.Fatalf("changed %v err %v calls %d", changed, err, len(f.scripts))
			}
			if len(f.scripts) > 1 {
				s := f.scripts[1]
				ssh := strings.Index(s, "ufw allow from '203.0.113.5' to any port 22")
				web := strings.Index(s, "ufw allow from '0.0.0.0/0' to any port 80")
				timer := strings.Index(s, "systemd-run --quiet")
				enable := strings.Index(s, "ufw --force enable")
				if ssh < 0 || web < 0 || timer < ssh || timer < web || enable < timer {
					t.Fatalf("unsafe activation sequence:\n%s", s)
				}
			}
			if tc.fail == 3 && len(f.scripts) > 3 {
				t.Fatal("rollback was cancelled after failed verification")
			}
		})
	}
}
func TestAWSFirewallRejectsLosingSSH(t *testing.T) {
	peer, err := awsSSHSource("203.0.113.5 43210 10.0.0.4 22\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"203.0.113.5/32", "0.0.0.0/0"} {
		r := roles.Role{Steps: []roles.Step{{Type: "firewall", State: "closed", Protocol: "tcp", Port: 22, Sources: []string{source}}}}
		if err := validateAWSSSHRules(r, peer); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if _, err := awsSSHSource("bad"); err == nil {
		t.Fatal("accepted invalid SSH connection")
	}
}

type firewallReportRunner struct{ firewallRunner }

func (f *firewallReportRunner) Run(ctx context.Context, script string) ([]byte, error) {
	out, err := f.firewallRunner.Run(ctx, script)
	if err == nil && strings.Contains(script, "KORTA_RESULT") {
		return []byte("KORTA_RESULT ok ufw rules current\n"), nil
	}
	return out, err
}

func TestAWSFirewallFinalReport(t *testing.T) {
	run := &firewallReportRunner{firewallRunner: firewallRunner{state: "inactive"}}
	role := roles.Role{Name: "web", Steps: []roles.Step{{Type: "aws"}, {Type: "firewall", State: "open", Port: 80, Protocol: "tcp", Sources: []string{"0.0.0.0/0"}}}}
	target := roles.Target{Name: "web", Connect: func(context.Context) (roles.Runner, roles.Host, error) { return run, roles.Host{Family: "apt"}, nil }}
	result := roles.HostResult{Instance: "web", Status: "changed", Steps: []roles.StepResult{{Step: 1, Name: "open 80", Status: "skipped", Detail: "no active firewall"}}}
	err := finishAWSFirewall(context.Background(), run, netip.MustParseAddr("203.0.113.5"), role, target, &result)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Steps) != 2 || result.Steps[0].Status != "ok" || result.Steps[0].Detail != "ufw rules current" || result.Steps[1].Status != "changed" || result.Steps[1].Name != "Enable UFW" {
		t.Fatalf("unexpected result: %+v", result.Steps)
	}
}

func TestAWSFirewallFailureAppearsInReport(t *testing.T) {
	run := &firewallReportRunner{firewallRunner: firewallRunner{state: "inactive", failAt: 3}}
	role := roles.Role{Name: "web", Steps: []roles.Step{{Type: "aws"}, {Type: "firewall", State: "open", Port: 80, Protocol: "tcp", Sources: []string{"0.0.0.0/0"}}}}
	result := roles.HostResult{Instance: "web", Steps: []roles.StepResult{{Step: 1, Status: "skipped"}}}
	err := finishAWSFirewall(context.Background(), run, netip.MustParseAddr("203.0.113.5"), role, roles.Target{}, &result)
	if err == nil || len(result.Steps) != 2 || result.Steps[1].Status != "failed" || !strings.Contains(result.Steps[1].Detail, "rollback") && !strings.Contains(result.Steps[1].Detail, "disabled") {
		t.Fatalf("result %+v error %v", result, err)
	}
}

func TestFinalizedApplyLogsFinalFirewallStatus(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	options, err := parse([]string{"apply", "role.md", "--yes"})
	if err != nil {
		t.Fatal(err)
	}
	var out, progress bytes.Buffer
	c := client{opts: options, out: &out, errOut: &progress, in: strings.NewReader("")}
	role := &localRole{name: "web", compiled: map[string]roles.Role{}, rollout: roles.Rollout{}}
	run := &firewallReportRunner{firewallRunner: firewallRunner{state: "inactive"}}
	target := roles.Target{ID: "web", Name: "web", Connect: func(context.Context) (roles.Runner, roles.Host, error) { return run, roles.Host{Family: "apt"}, nil }, Prepare: func(roles.Host) (roles.Role, error) {
		return roles.Role{Name: "web", Steps: []roles.Step{{Type: "firewall", State: "open", Port: 80, Protocol: "tcp", Sources: []string{"0.0.0.0/0"}}}}, nil
	}}
	plan := roles.Run{Kind: "plan", RoleID: "web"}
	plan.Add(roles.HostResult{Instance: "web", Status: "changed", Steps: []roles.StepResult{{Step: 1, Name: "port", Status: "changed"}}})
	if err := c.localApplyFinalized(context.Background(), role, []roles.Target{target}, plan, func(h *roles.HostResult) error {
		h.Steps = append(h.Steps, roles.StepResult{Step: 2, Name: "Enable UFW", Status: "changed", Detail: "enabled UFW"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Enable UFW") {
		t.Fatalf("missing final output: %s", out.String())
	}
	paths, err := filepath.Glob(filepath.Join(os.Getenv("XDG_STATE_HOME"), "korta", "runs", "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("logs %v %v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || !strings.Contains(string(data), "Enable UFW") {
		t.Fatalf("missing final log: %s %v", data, err)
	}
}
