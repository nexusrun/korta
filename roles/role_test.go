package roles

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pubKey(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " ops@laptop"
}

func role(t *testing.T, steps string) Role {
	t.Helper()
	var r Role
	if err := json.Unmarshal([]byte(`{"name":"baseline","targets":{"labels":{"env":"prod"}},"steps":`+steps+`}`), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNormalize(t *testing.T) {
	for _, tc := range []struct{ name, steps, err string }{
		{"packages", `[{"type":"packages","packages":["nginx","curl"]}]`, ""},
		{"patch defaults", `[{"type":"patch"}]`, ""},
		{"file", `[{"type":"file","path":"/etc/motd","content":"hi"}]`, ""},
		{"no steps", `[]`, "1-50 steps"},
		{"unknown", `[{"type":"reboot"}]`, "unknown step type"},
		{"package injection", `[{"type":"packages","packages":["curl; rm -rf /"]}]`, "invalid package"},
		{"path traversal", `[{"type":"file","path":"/etc/../root/x","content":"x"}]`, "absolute, without .."},
		{"protected path", `[{"type":"file","path":"/proc/sys/x","content":"x"}]`, "does not manage"},
		{"bad mode", `[{"type":"file","path":"/etc/x","mode":"rwx"}]`, "octal"},
		{"service injection", `[{"type":"service","service":"nginx;reboot"}]`, "service name"},
		{"sysctl injection", `[{"type":"sysctl","settings":{"vm.swappiness":"10\nkernel.x=1"}}]`, "invalid sysctl"},
		{"root user", `[{"type":"user","user":"root"}]`, "other than root"},
		{"bad key", `[{"type":"user","user":"deploy","authorizedKeys":["not a key"]}]`, "valid SSH public key"},
		{"firewall no source", `[{"type":"firewall","port":443}]`, "source networks"},
		{"empty command", `[{"type":"command","run":"  "}]`, "needs a script"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := role(t, tc.steps)
			err := r.Normalize()
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("got %v, want %q", err, tc.err)
			}
		})
	}
	r := role(t, `[{"type":"patch"}]`)
	r.Targets = Targets{}
	if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), "targets") && !strings.Contains(err.Error(), "target") {
		t.Fatalf("role without targets accepted: %v", err)
	}
}

func TestScriptsRenderValidShellForEveryStep(t *testing.T) {
	enabled := true
	key := pubKey(t)
	steps := []Step{
		{Type: "packages", Packages: []string{"nginx", "curl"}},
		{Type: "packages", State: "latest", Packages: []string{"openssl"}},
		{Type: "packages", State: "absent", Packages: []string{"telnet"}},
		{Type: "patch", Scope: "all", Reboot: "if-required", Exclude: []string{"kernel"}},
		{Type: "patch", Scope: "security", Reboot: "never"},
		{Type: "file", Path: "/etc/nginx/conf.d/app.conf", Content: "server { return 200 'it''s $host'; }\nEOF\n'; rm -rf / #"},
		{Type: "file", Path: "/etc/old.conf", State: "absent"},
		{Type: "service", Service: "nginx", Enabled: &enabled, RestartOnChange: true},
		{Type: "service", Service: "cups", State: "stopped"},
		{Type: "sysctl", Settings: map[string]string{"vm.swappiness": "10", "net.core.somaxconn": "1024"}},
		{Type: "user", User: "deploy", Groups: []string{"wheel"}, Shell: "/bin/bash", AuthorizedKeys: []string{key}},
		{Type: "user", User: "olduser", State: "absent"},
		{Type: "firewall", Port: 443, Sources: []string{"10.0.0.0/8", "fd00::/64"}},
		{Type: "firewall", Port: 23, State: "closed", Sources: []string{"0.0.0.0/0"}},
		{Type: "command", Run: "echo 'quoted' \"$HOME\"; touch /opt/done", Creates: "/opt/done"},
		{Type: "group", Group: "apps", System: true},
		{Type: "group", Group: "legacy", State: "absent"},
		{Type: "directory", Path: "/opt/app", Owner: "deploy", Group: "apps", Mode: "0750"},
		{Type: "file", Path: "/etc/nginx/conf.d/a.conf", Content: "server {}\n", Check: "nginx -t -c '/etc/nginx/nginx.conf'"},
		{Type: "file", Path: "/etc/sudoers.d/ops", Content: "ops ALL=(ALL) ALL\n", Mode: "0440", Check: "visudo -cf %s"},
		{Type: "service", Service: "nginx", ReloadOnChange: true},
	}
	r := Role{Name: "baseline", Steps: steps, Targets: Targets{InstanceIDs: []string{"ins_1"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, h := range []Host{{Family: "apt", Distro: "ubuntu"}, {Family: "rpm", Distro: "rocky"}} {
		for _, apply := range []bool{false, true} {
			for i, s := range r.Steps {
				script, err := Script(r.Name, s, h, apply, true)
				if err != nil {
					t.Fatalf("%s step %d: %v", h.Family, i, err)
				}
				if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
					t.Fatalf("%s apply=%v step %d (%s): %s %v\n%s", h.Family, apply, i, s.Type, out, err, script)
				}
				if strings.Contains(script, "rm -rf /") || strings.Contains(script, "echo 'quoted'") {
					t.Fatalf("raw content reached the script for step %d", i)
				}
				if !apply {
					for _, mutating := range []string{"apt-get install", "apt-get remove", "dnf install", "dnf remove", "dnf -y", "useradd", "userdel", "groupadd", "groupdel", "mkdir", "chown", "systemctl reboot\"", "mv -f", "sysctl -p", "--add-rich-rule", "todo=1; ufw", "sh \"$tmp\""} {
						if strings.Contains(script, mutating) {
							t.Fatalf("plan for step %d (%s) contains %q", i, s.Type, mutating)
						}
					}
				}
			}
		}
	}
	if s, _ := Script("x", Step{Type: "service", Service: "sshd", State: "started"}, Host{Family: "apt"}, true, false); !strings.Contains(s, "systemctl show -p Id --value") {
		t.Fatal("service steps must resolve unit aliases")
	}
	if _, err := Script("x", Step{Type: "patch", Scope: "security", Reboot: "never"}, Host{Family: "rpm", Distro: "centos"}, false, false); err == nil {
		t.Fatal("security patching on CentOS Stream accepted")
	}
}

func TestParseResultRiskAndHash(t *testing.T) {
	status, detail, ok := ParseResult([]byte("noise\nKORTA_RESULT changed would install: nginx\n"))
	if !ok || status != "changed" || detail != "would install: nginx" {
		t.Fatal(status, detail, ok)
	}
	if _, _, ok := ParseResult([]byte("KORTA_RESULT pwned yes")); ok {
		t.Fatal("unknown status accepted")
	}
	r := role(t, `[{"type":"patch","reboot":"always"},{"type":"command","run":"true"},{"type":"packages","state":"absent","packages":["x"]}]`)
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(r.Risky()) != 3 || !r.HasCommand() {
		t.Fatal(r.Risky())
	}
	h := r.Hash()
	r.Steps[0].Reboot = "never"
	if r.Hash() == h {
		t.Fatal("hash ignores step changes")
	}
	r.Description = "docs only"
	if r.Hash() != r.Hash() {
		t.Fatal("unstable hash")
	}
}

// TestPatchRebootDecision runs the real rendered RPM patch script against
// fake dnf, rpm, uname and systemd-run commands.
func TestPatchRebootDecision(t *testing.T) {
	for _, tc := range []struct {
		name, rpmOut, want string
		reboots            bool
	}{
		{"no kernel package (containers)", "package kernel-core is not installed\npackage kernel is not installed\n", "KORTA_RESULT ok", false},
		{"running newest kernel", "package kernel is not installed\nkernel-core-5.14.0-427.el9.x86_64  Mon 01 Jan\n", "KORTA_RESULT ok", false},
		{"newer kernel installed", "kernel-core-5.14.0-503.el9.x86_64  Tue 02 Jan\nkernel-core-5.14.0-427.el9.x86_64  Mon 01 Jan\n", "KORTA_RESULT reboot", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fake := map[string]string{
				"dnf":         "#!/bin/sh\nexit 0\n",
				"rpm":         "#!/bin/sh\nprintf '%s' '" + tc.rpmOut + "'\n",
				"uname":       "#!/bin/sh\necho 5.14.0-427.el9.x86_64\n",
				"systemd-run": "#!/bin/sh\ntouch " + dir + "/rebooted\n",
			}
			for name, body := range fake {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			s := Step{Type: "patch", Scope: "all", Reboot: "if-required"}
			script, err := Script("x", s, Host{Family: "rpm", Distro: "rocky"}, true, false)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			_, statErr := os.Stat(filepath.Join(dir, "rebooted"))
			if !strings.Contains(string(out), tc.want) || (statErr == nil) != tc.reboots {
				t.Fatalf("output %q, rebooted %v", out, statErr == nil)
			}
		})
	}
}
