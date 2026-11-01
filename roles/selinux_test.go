package roles

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSELinuxMarkdownValidation(t *testing.T) {
	md := "# SELinux\n- mode enforcing\n- boolean httpd_can_network_connect on\n- port tcp 8080 http_port_t\n- fcontext /srv/app.example httpd_sys_content_t recursive\n"
	r := Role{Name: "selinux", Markdown: md, Targets: Targets{InstanceIDs: []string{"host"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	round := Role{Name: "selinux", Markdown: ToMarkdown(r.Steps), Targets: r.Targets}
	if err := round.Normalize(); err != nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if len(round.Steps) != 4 || round.Steps[3].Path != "/srv/app.example" || !round.Steps[3].Recursive {
		t.Fatalf("%+v", round.Steps)
	}
	if selinuxFileSpec(round.Steps[3]) != `/srv/app\.example(/.*)?` {
		t.Fatal(selinuxFileSpec(round.Steps[3]))
	}
	for _, bad := range []string{"- mode disabled", "- boolean foo maybe", "- port tcp 0 http_port_t", "- port tcp 80 bad;id", "- fcontext /proc/foo httpd_t", "- fcontext /srv/foo/ httpd_t", "- mode enforcing\n- mode permissive"} {
		role := Role{Name: "selinux", Markdown: "# SELinux\n" + bad, Targets: r.Targets}
		if err := role.Normalize(); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSELinuxScripts(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	config := filepath.Join(dir, "config")
	path := filepath.Join(dir, "app")
	if err := os.WriteFile(config, []byte("# SELinux\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	tools := map[string]string{
		"getenforce":   "#!/bin/sh\nprintf '%s\\n' \"$SELINUX_RUNTIME\"\n",
		"setenforce":   "#!/bin/sh\nprintf 'setenforce %s\\n' \"$*\" >> \"$LOG\"\n",
		"getsebool":    "#!/bin/sh\nprintf '%s --> %s\\n' \"$1\" \"$BOOL_RUNTIME\"\n",
		"setsebool":    "#!/bin/sh\nprintf 'setsebool %s\\n' \"$*\" >> \"$LOG\"\n",
		"semanage":     "#!/bin/sh\ncase \"$1:$2\" in boolean:-l) printf '%s\\n' \"$BOOL_LIST\";; port:-l) printf '%s\\n' \"$PORT_LIST\";; fcontext:-l) printf '%s\\n' \"$FCONTEXT_LIST\";; *) printf 'semanage %s\\n' \"$*\" >> \"$LOG\";; esac\n",
		"matchpathcon": "#!/bin/sh\nprintf 'system_u:object_r:httpd_sys_content_t:s0\\n'\n",
		"restorecon":   "#!/bin/sh\ncase \"$1\" in -n) printf '%s' \"$RELABEL_NEEDED\";; *) printf 'restorecon %s\\n' \"$*\" >> \"$LOG\";; esac\n",
	}
	for name, body := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LOG", log)
	t.Setenv("SELINUX_RUNTIME", "Enforcing")
	t.Setenv("BOOL_RUNTIME", "off")
	t.Setenv("BOOL_LIST", "httpd_can_network_connect (off , off) Allow network")
	t.Setenv("PORT_LIST", "http_port_t tcp 80, 443, 8000-8002")
	t.Setenv("FCONTEXT_LIST", "")
	t.Setenv("RELABEL_NEEDED", "")
	run := func(s Step, apply bool) (string, error) {
		t.Helper()
		script, err := Script("test", s, Host{}, apply, false)
		if err != nil {
			t.Fatal(err)
		}
		script = strings.ReplaceAll(script, "/etc/selinux/config", config)
		script = strings.ReplaceAll(script, "/etc/selinux/.xela-config.", filepath.Join(dir, ".xela-config."))
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		return string(out), err
	}
	enabled := true
	steps := []Step{{Type: "selinux-mode", SELinuxMode: "permissive"}, {Type: "selinux-boolean", SELinuxBoolean: "httpd_can_network_connect", Enabled: &enabled}, {Type: "selinux-port", Protocol: "tcp", Port: 8080, SELinuxType: "http_port_t"}, {Type: "selinux-fcontext", Path: path, SELinuxType: "httpd_sys_content_t", Recursive: true}}
	for _, s := range steps {
		out, err := run(s, false)
		if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
			t.Fatalf("plan %s: %s %v", s.Type, out, err)
		}
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("plan ran mutation")
	}
	for _, s := range steps {
		out, err := run(s, true)
		if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
			t.Fatalf("apply %s: %s %v", s.Type, out, err)
		}
	}
	b, _ := os.ReadFile(config)
	if !strings.Contains(string(b), "SELINUX=permissive") || !strings.Contains(string(b), "SELINUXTYPE=targeted") {
		t.Fatal(string(b))
	}
	b, _ = os.ReadFile(log)
	for _, want := range []string{"setenforce 0", "setsebool -P httpd_can_network_connect on", "semanage port -a -t http_port_t -p tcp 8080", "semanage fcontext -a -t httpd_sys_content_t", "restorecon -R"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in %s", want, b)
		}
	}
	out, err := run(Step{Type: "selinux-port", Protocol: "tcp", Port: 8001, SELinuxType: "ssh_port_t"}, false)
	if err == nil || !strings.Contains(out, "different SELinux range") {
		t.Fatalf("range: %s %v", out, err)
	}
	t.Setenv("SELINUX_RUNTIME", "Permissive")
	t.Setenv("BOOL_RUNTIME", "on")
	t.Setenv("BOOL_LIST", "httpd_can_network_connect (on , on) Allow network")
	t.Setenv("FCONTEXT_LIST", selinuxFileSpec(steps[3])+" all files system_u:object_r:httpd_sys_content_t:s0")
	converged := append([]Step{}, steps...)
	converged[2].Port = 80
	for _, step := range converged {
		out, err := run(step, false)
		if err != nil || !strings.Contains(out, "KORTA_RESULT ok") {
			t.Fatalf("converged %s: %s %v", step.Type, out, err)
		}
	}
	t.Setenv("RELABEL_NEEDED", "would relabel")
	out, err = run(steps[3], false)
	if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
		t.Fatalf("relabel: %s %v", out, err)
	}
	t.Setenv("SELINUX_RUNTIME", "Disabled")
	out, err = run(steps[1], false)
	if err == nil || !strings.Contains(out, "disabled") {
		t.Fatalf("disabled: %s %v", out, err)
	}
}
