package roles

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostSettingsMarkdownAndValidation(t *testing.T) {
	md := "# Hostname\n- Web-01.example.com\n\n# Time\n- timezone UTC\n- ntp enabled\n\n# DNS\n- nameservers 1.1.1.1, 2001:4860:4860::8888\n"
	r := Role{Name: "host", Markdown: md, Targets: Targets{InstanceIDs: []string{"test"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(r.Steps) != 4 || r.Steps[0].Hostname != "web-01.example.com" || r.Steps[2].NTP == nil || !*r.Steps[2].NTP || len(r.Steps[3].Nameservers) != 2 {
		t.Fatalf("%+v", r.Steps)
	}
	round := Role{Name: "host", Markdown: ToMarkdown(r.Steps), Targets: r.Targets}
	if err := round.Normalize(); err != nil || len(round.Steps) != 4 {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	for _, bad := range []string{"# Hostname\n- invalid;id", "# Hostname\n- a..b", "# Time\n- timezone ../../etc/passwd", "# Time\n- ntp maybe", "# DNS\n- nameservers 1.1.1.1, 1.1.1.1", "# DNS\n- nameservers 1.1.1.1;id", "# Hostname\n- a\n- b"} {
		r := Role{Name: "host", Markdown: bad, Targets: Targets{InstanceIDs: []string{"test"}}}
		if err := r.Normalize(); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestDNSPlanAndApplyPreservesOtherResolverSettings(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "resolv.conf")
	original := "search internal.example\noptions timeout:2\nnameserver 10.0.0.1\n"
	if err := os.WriteFile(file, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	tools := map[string]string{"systemctl": "#!/bin/sh\ncase \"$1\" in show) exit 0;; is-active) exit 3;; esac\nexit 1\n", "chmod": "#!/bin/sh\nexit 0\n", "chown": "#!/bin/sh\nexit 0\n", "restorecon": "#!/bin/sh\nexit 0\n"}
	for name, script := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	step := Step{Type: "dns", Nameservers: []string{"1.1.1.1", "8.8.8.8"}}
	run := func(apply bool) (string, error) {
		s, err := Script("test", step, Host{}, apply, false)
		if err != nil {
			return "", err
		}
		s = strings.ReplaceAll(s, "/etc/resolv.conf", file)
		s = strings.ReplaceAll(s, "/etc/.xela-resolv.", filepath.Join(dir, ".xela-resolv."))
		out, err := exec.Command("sh", "-c", s).CombinedOutput()
		return string(out), err
	}
	out, err := run(false)
	if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
		t.Fatalf("%s %v", out, err)
	}
	if b, _ := os.ReadFile(file); string(b) != original {
		t.Fatal("plan modified DNS")
	}
	out, err = run(true)
	if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
		t.Fatalf("%s %v", out, err)
	}
	b, _ := os.ReadFile(file)
	if string(b) != "search internal.example\noptions timeout:2\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n" {
		t.Fatalf("%q", b)
	}
	out, err = run(false)
	if err != nil || !strings.Contains(out, "KORTA_RESULT ok") {
		t.Fatalf("%s %v", out, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\ncase \"$1\" in show|is-active) exit 0;; esac\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if out, err = run(true); err == nil || !strings.Contains(out, "active") {
		t.Fatalf("accepted active resolver manager: %s %v", out, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "other"), file); err != nil {
		t.Fatal(err)
	}
	if out, err = run(true); err == nil {
		t.Fatalf("accepted a symlink: %s", out)
	}
}

func TestHostnameAndTimePlanApplyAndConverge(t *testing.T) {
	dir := t.TempDir()
	hostname := filepath.Join(dir, "hostname")
	timezone := filepath.Join(dir, "timezone")
	ntp := filepath.Join(dir, "ntp")
	for file, value := range map[string]string{hostname: "old.example", timezone: "Europe/London", ntp: "no"} {
		if err := os.WriteFile(file, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tools := map[string]string{
		"hostnamectl": "#!/bin/sh\ncase \"$1\" in --static) cat \"$HOST_STATE\";; set-hostname) printf %s \"$2\" > \"$HOST_STATE\";; *) exit 1;; esac\n",
		"timedatectl": "#!/bin/sh\ncase \"$1:$2\" in show:--property=Timezone) cat \"$TZ_STATE\";; show:--property=NTP) cat \"$NTP_STATE\";; set-timezone:*) printf %s \"$2\" > \"$TZ_STATE\";; set-ntp:true) printf yes > \"$NTP_STATE\";; set-ntp:false) printf no > \"$NTP_STATE\";; *) exit 1;; esac\n",
	}
	for name, script := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOST_STATE", hostname)
	t.Setenv("TZ_STATE", timezone)
	t.Setenv("NTP_STATE", ntp)
	enabled := true
	for _, step := range []Step{{Type: "hostname", Hostname: "web-01"}, {Type: "timezone", Timezone: "UTC"}, {Type: "ntp", NTP: &enabled}} {
		run := func(apply bool) (string, error) {
			s, err := Script("test", step, Host{}, apply, false)
			if err != nil {
				return "", err
			}
			out, err := exec.Command("sh", "-c", s).CombinedOutput()
			return string(out), err
		}
		before, _ := os.ReadFile(hostname)
		out, err := run(false)
		if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
			t.Fatalf("%s: %s %v", step.Type, out, err)
		}
		after, _ := os.ReadFile(hostname)
		if !bytes.Equal(before, after) {
			t.Fatal("plan modified host")
		}
		out, err = run(true)
		if err != nil || !strings.Contains(out, "KORTA_RESULT changed") {
			t.Fatalf("%s: %s %v", step.Type, out, err)
		}
		out, err = run(false)
		if err != nil || !strings.Contains(out, "KORTA_RESULT ok") {
			t.Fatalf("%s: %s %v", step.Type, out, err)
		}
	}
}
