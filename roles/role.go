// Package roles defines reusable host configuration: typed, idempotent steps
// such as patching, packages, files and services, applied to instances after
// a plan has been reviewed and approved.
package roles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Role is the desired configuration. Steps run in order on every target.
// When Markdown is set, Steps are compiled from it, and Files holds the
// template files its Files bullets name with "from", by relative path.
type Role struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Markdown    string            `json:"markdown,omitempty"`
	Files       map[string]string `json:"files,omitempty"`
	Steps       []Step            `json:"steps"`
	Targets     Targets           `json:"targets"`
	Rollout     Rollout           `json:"rollout"`
}

// Targets selects instances by ID, by labels (all must match), or both.
type Targets struct {
	InstanceIDs []string          `json:"instanceIDs,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// Rollout applies to BatchSize hosts at a time and stops after a failed batch
// unless ContinueOnFailure is set.
type Rollout struct {
	BatchSize         int  `json:"batchSize"`
	ContinueOnFailure bool `json:"continueOnFailure,omitempty"`
}

// Step is one typed action. Only the fields of its Type are used.
type Step struct {
	AWS  *AWSInstance `json:"aws,omitempty"`
	Type string       `json:"type"` // packages, patch, group, user, directory, file, service, sysctl, firewall, command
	Name string       `json:"name,omitempty"`

	// packages
	State    string   `json:"state,omitempty"` // packages: present, absent, latest; file/user: present, absent; service: started, stopped; firewall: open, closed
	Packages []string `json:"packages,omitempty"`

	// patch
	Scope   string   `json:"scope,omitempty"`  // security or all
	Reboot  string   `json:"reboot,omitempty"` // never, if-required, always
	Exclude []string `json:"exclude,omitempty"`

	// file and directory; Group is also the name of a group step
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
	Source  string `json:"source,omitempty"` // template file the content comes from
	Raw     bool   `json:"raw,omitempty"`    // copy Source exactly, without variables
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	Mode    string `json:"mode,omitempty"`

	// group
	System bool `json:"system,omitempty"`

	// Check validates a new file before it stays: a command run after the
	// file is in place (the old file is restored if it fails), or, with %s,
	// run on the new content before it replaces the old file.
	Check string `json:"check,omitempty"`

	// service
	Service         string `json:"service,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
	RestartOnChange bool   `json:"restartOnChange,omitempty"`
	ReloadOnChange  bool   `json:"reloadOnChange,omitempty"`

	// sysctl
	Settings map[string]string `json:"settings,omitempty"`

	// user
	User           string   `json:"user,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Shell          string   `json:"shell,omitempty"`
	AuthorizedKeys []string `json:"authorizedKeys,omitempty"`

	// firewall
	Port     int      `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"` // tcp or udp
	Sources  []string `json:"sources,omitempty"`

	// command: high-risk, needs explicit confirmation on approval
	Run     string `json:"run,omitempty"`
	Creates string `json:"creates,omitempty"` // skip when this path exists
}

var (
	roleNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	packagePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+_:-]{0,127}$`)
	servicePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,127}$`)
	pathPattern     = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]{1,250}$`)
	accountPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	modePattern     = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	sysctlKey       = regexp.MustCompile(`^[a-z0-9_.-]{1,128}$`)
	sysctlValue     = regexp.MustCompile(`^[A-Za-z0-9 _.,:/-]{1,200}$`)
	labelPattern    = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,63}$`)
	protectedPaths  = []string{"/proc", "/sys", "/dev", "/run", "/boot"}
)

const (
	maxSteps       = 50
	maxFileBytes   = 256 * 1024
	maxCommandSize = 32 * 1024
	// A role holds up to 50 steps, files of up to 256 KiB among them.
	maxMarkdownBytes = 1024 * 1024
)

// Normalize validates the role and fills defaults.
// Normalize validates the role and fills defaults. A Markdown role is
// compiled with its # Variables defaults and sample host facts, which shows
// its steps and catches mistakes before it runs anywhere.
func (r *Role) Normalize() error {
	vars, err := Variables(r.Markdown)
	if err != nil {
		return err
	}
	for k, v := range SampleFacts() {
		vars[k] = v
	}
	for _, name := range SecretRefs(r.Markdown, r.Files) {
		vars[SecretPrefix+name] = SecretPlaceholder
	}
	return r.Compile(vars)
}

// Compile renders the role's Markdown and template files with vars, then
// validates it. The Markdown and Files stay templates; only Steps change.
func (r *Role) Compile(vars map[string]string) error {
	if !roleNamePattern.MatchString(r.Name) {
		return fmt.Errorf("role name must be lowercase letters, digits and -")
	}
	if r.Markdown != "" {
		if _, err := ParseAWS(r.Markdown); err != nil {
			return err
		}
		size := len(r.Markdown)
		for name, content := range r.Files {
			if err := checkSource(name); err != nil {
				return err
			}
			size += len(name) + len(content)
		}
		if size > maxMarkdownBytes {
			return fmt.Errorf("the role and its template files must be at most %d bytes", maxMarkdownBytes)
		}
		rendered, err := Render(r.Markdown, vars)
		if err != nil {
			return err
		}
		steps, err := ParseMarkdown(rendered)
		if err != nil {
			return err
		}
		for i := range steps {
			if steps[i].Source == "" {
				continue
			}
			if steps[i].Content, err = r.source(steps[i], vars); err != nil {
				return err
			}
		}
		r.Steps = steps
	}
	if len(r.Description) > 2000 {
		return fmt.Errorf("description must be at most 2000 characters")
	}
	if len(r.Steps) == 0 || len(r.Steps) > maxSteps {
		return fmt.Errorf("a role needs 1-%d steps", maxSteps)
	}
	if r.AWS() == nil && len(r.Targets.InstanceIDs) == 0 && len(r.Targets.Labels) == 0 {
		return fmt.Errorf("choose target instances or labels")
	}
	for k, v := range r.Targets.Labels {
		if !labelPattern.MatchString(k) || !labelPattern.MatchString(v) {
			return fmt.Errorf("invalid target label %q", k)
		}
	}
	if r.Rollout.BatchSize == 0 {
		r.Rollout.BatchSize = 1
	}
	if r.Rollout.BatchSize < 1 || r.Rollout.BatchSize > 100 {
		return fmt.Errorf("rollout batchSize must be 1-100")
	}
	for i := range r.Steps {
		if r.Steps[i].Type == "aws-instance" && i != 0 {
			return fmt.Errorf("AWS instance must be the first step")
		}
		if err := r.Steps[i].normalize(); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, r.Steps[i].Type, err)
		}
	}
	return nil
}

func (s *Step) normalize() error {
	if len(s.Name) > 120 {
		return fmt.Errorf("name must be at most 120 characters")
	}
	if s.Type != "aws-instance" && s.AWS != nil {
		return fmt.Errorf("aws settings require an aws-instance step")
	}
	switch s.Type {
	case "aws-instance":
		if s.AWS == nil {
			return fmt.Errorf("AWS settings are required")
		}
		return s.AWS.normalize()
	case "packages":
		if s.State == "" {
			s.State = "present"
		}
		if !oneOf(s.State, "present", "absent", "latest") || len(s.Packages) == 0 || len(s.Packages) > 100 {
			return fmt.Errorf("needs state present, absent or latest and 1-100 packages")
		}
		return all(s.Packages, packagePattern, "package")
	case "patch":
		if s.Scope == "" {
			s.Scope = "security"
		}
		if s.Reboot == "" {
			s.Reboot = "if-required"
		}
		if !oneOf(s.Scope, "security", "all") || !oneOf(s.Reboot, "never", "if-required", "always") {
			return fmt.Errorf("scope must be security or all; reboot never, if-required or always")
		}
		return all(s.Exclude, packagePattern, "excluded package")
	case "file":
		if s.State == "" {
			s.State = "present"
		}
		if !oneOf(s.State, "present", "absent") {
			return fmt.Errorf("state must be present or absent")
		}
		if err := checkPath(s.Path); err != nil {
			return err
		}
		if len(s.Content) > maxFileBytes {
			return fmt.Errorf("content must be at most %d bytes", maxFileBytes)
		}
		if s.Owner == "" {
			s.Owner = "root"
		}
		if s.Group == "" {
			s.Group = s.Owner
		}
		if s.Mode == "" {
			s.Mode = "0644"
		}
		if !accountPattern.MatchString(s.Owner) || !accountPattern.MatchString(s.Group) || !modePattern.MatchString(s.Mode) {
			return fmt.Errorf("owner and group must be account names; mode an octal such as 0644")
		}
		if len(s.Check) > 1000 || strings.ContainsAny(s.Check, "\n\r\x00") || (s.Check != "" && s.State == "absent") {
			return fmt.Errorf("check must be a single command of at most 1000 characters, for a file being written")
		}
	case "directory":
		if s.State == "" {
			s.State = "present"
		}
		if s.State != "present" {
			return fmt.Errorf("Korta only creates directories; remove them with a command step")
		}
		if err := checkPath(s.Path); err != nil {
			return err
		}
		if s.Owner == "" {
			s.Owner = "root"
		}
		if s.Group == "" {
			s.Group = s.Owner
		}
		if s.Mode == "" {
			s.Mode = "0755"
		}
		if !accountPattern.MatchString(s.Owner) || !accountPattern.MatchString(s.Group) || !modePattern.MatchString(s.Mode) {
			return fmt.Errorf("owner and group must be account names; mode an octal such as 0755")
		}
	case "group":
		if s.State == "" {
			s.State = "present"
		}
		if !accountPattern.MatchString(s.Group) || s.Group == "root" || !oneOf(s.State, "present", "absent") {
			return fmt.Errorf("needs a group name other than root and state present or absent")
		}
	case "service":
		if s.State == "" {
			s.State = "started"
		}
		if !servicePattern.MatchString(s.Service) || !oneOf(s.State, "started", "stopped") {
			return fmt.Errorf("needs a service name and state started or stopped")
		}
	case "sysctl":
		if len(s.Settings) == 0 {
			return fmt.Errorf("needs at least one setting")
		}
		for k, v := range s.Settings {
			if !sysctlKey.MatchString(k) || !sysctlValue.MatchString(v) {
				return fmt.Errorf("invalid sysctl setting %q", k)
			}
		}
	case "user":
		if s.State == "" {
			s.State = "present"
		}
		if !accountPattern.MatchString(s.User) || s.User == "root" || !oneOf(s.State, "present", "absent") {
			return fmt.Errorf("needs a user name other than root and state present or absent")
		}
		if err := all(s.Groups, accountPattern, "group"); err != nil {
			return err
		}
		if s.Shell != "" && !pathPattern.MatchString(s.Shell) {
			return fmt.Errorf("invalid shell %q", s.Shell)
		}
		for i, k := range s.AuthorizedKeys {
			pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			if err != nil {
				return fmt.Errorf("authorized key %d is not a valid SSH public key", i+1)
			}
			s.AuthorizedKeys[i] = strings.TrimSpace(strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n") + " " + cleanComment(comment))
		}
	case "firewall":
		if s.State == "" {
			s.State = "open"
		}
		if s.Protocol == "" {
			s.Protocol = "tcp"
		}
		if s.Port < 1 || s.Port > 65535 || !oneOf(s.Protocol, "tcp", "udp") || !oneOf(s.State, "open", "closed") || len(s.Sources) == 0 {
			return fmt.Errorf("needs port 1-65535, protocol tcp or udp, state open or closed and source networks")
		}
		for i, c := range s.Sources {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return fmt.Errorf("source %q must be a network such as 10.0.0.0/16", c)
			}
			s.Sources[i] = p.Masked().String()
		}
	case "command":
		if strings.TrimSpace(s.Run) == "" || len(s.Run) > maxCommandSize {
			return fmt.Errorf("needs a script of at most %d bytes", maxCommandSize)
		}
		if s.Creates != "" {
			if err := checkPath(s.Creates); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown step type; use packages, patch, group, user, directory, file, service, sysctl, firewall or command")
	}
	return nil
}

// Risky reports why a role needs extra care on approval.
func (r Role) Risky() []string {
	out := []string{}
	if r.AWS() != nil {
		n := r.AWS().Count
		what := "a billable EC2 instance"
		if n > 1 {
			what = fmt.Sprintf("%d billable EC2 instances", n)
		}
		out = append(out, "creates "+what+"; configuration is checked after launch")
	}
	for i, s := range r.Steps {
		switch {
		case s.Type == "command":
			out = append(out, fmt.Sprintf("step %d runs a custom script as root", i+1))
		case s.Check != "":
			out = append(out, fmt.Sprintf("step %d runs a check command as root: %s", i+1, s.Check))
		case s.Type == "patch" && s.Reboot != "never":
			out = append(out, fmt.Sprintf("step %d may reboot hosts", i+1))
		case s.Type == "packages" && s.State == "absent":
			out = append(out, fmt.Sprintf("step %d removes packages", i+1))
		case s.Type == "user" && s.State == "absent":
			out = append(out, fmt.Sprintf("step %d removes a user", i+1))
		case s.Type == "group" && s.State == "absent":
			out = append(out, fmt.Sprintf("step %d removes a group", i+1))
		case s.Type == "firewall" && s.State == "closed":
			out = append(out, fmt.Sprintf("step %d closes a firewall port", i+1))
		}
	}
	return out
}

// HasCommand reports whether approval needs the command confirmation.
func (r Role) HasCommand() bool {
	for _, s := range r.Steps {
		if s.Type == "command" || s.Check != "" {
			return true
		}
	}
	return false
}

// Hash identifies the exact content that was planned and approved.
func (r Role) Hash() string {
	b, _ := json.Marshal(struct {
		Markdown string            `json:"markdown"`
		Files    map[string]string `json:"files"`
		Steps    []Step            `json:"steps"`
		Targets  Targets           `json:"targets"`
		Rollout  Rollout           `json:"rollout"`
	}{r.Markdown, r.Files, r.Steps, r.Targets, r.Rollout})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var sourcePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,250}$`)

// checkSource accepts template file paths inside the role's folder.
func checkSource(p string) error {
	if !sourcePattern.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("template file %q must be a path inside the role's folder, such as templates/nginx.conf", p)
	}
	return nil
}

// source renders a file step's template file with the same variables.
func (r *Role) source(s Step, vars map[string]string) (string, error) {
	content, ok := r.Files[s.Source]
	if !ok {
		return "", fmt.Errorf("template file %s for %s is missing; keep it next to the role file, which korta sends with the role", s.Source, s.Path)
	}
	if !s.Raw {
		var err error
		if content, err = RenderFile(content, vars); err != nil {
			return "", fmt.Errorf("%s: %w", s.Source, err)
		}
	}
	if len(content) > maxFileBytes {
		return "", fmt.Errorf("%s: the file must be at most %d bytes", s.Source, maxFileBytes)
	}
	return content, nil
}

func checkPath(p string) error {
	if !pathPattern.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return fmt.Errorf("path must be absolute, without .. or special characters")
	}
	for _, protected := range protectedPaths {
		if p == protected || strings.HasPrefix(p, protected+"/") {
			return fmt.Errorf("path %s is under %s, which Korta does not manage", p, protected)
		}
	}
	return nil
}

func all(values []string, p *regexp.Regexp, what string) error {
	for _, v := range values {
		if !p.MatchString(v) {
			return fmt.Errorf("invalid %s %q", what, v)
		}
	}
	return nil
}

func oneOf(v string, options ...string) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}

func cleanComment(c string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\'' || r == '\\' {
			return -1
		}
		return r
	}, c)
}
