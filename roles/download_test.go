package roles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sumA = "6809dd0b3ec45fd6e992c19071d6b5253aed3ead7bf0686885a51d85c6643c66"
	sumB = "627382b9723c642411c33f48861134ebe893e70a63bcc8b3fc0619cd0bfac4be"
)

func downloadRole(body string) Role {
	return Role{Name: "tools", Markdown: body, Targets: Targets{InstanceIDs: []string{"host"}}}
}

func TestDownloadMarkdown(t *testing.T) {
	md := "# Downloads\n- /usr/local/bin/node_exporter from `https://example.com/node_exporter-1.8.2.linux-{{ os.arch }}.tar.gz`\n" +
		"  - sha256 amd64: " + strings.ToUpper(sumA) + "\n  - sha256  arm64: " + sumB + "\n  - extract: node_exporter-1.8.2.linux-{{ os.arch }}/node_exporter\n  - owner: app:apps\n  - mode: 0755\n"
	r := downloadRole(md)
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	s := r.Steps[0]
	if len(r.Steps) != 1 || s.Type != "download" || s.State != "present" || s.Path != "/usr/local/bin/node_exporter" ||
		s.URL != "https://example.com/node_exporter-1.8.2.linux-amd64.tar.gz" || s.Checksums["amd64"] != sumA || s.Checksums["arm64"] != sumB ||
		s.Extract != "node_exporter-1.8.2.linux-amd64/node_exporter" || s.Owner != "app" || s.Group != "apps" || s.Mode != "0755" {
		t.Fatalf("%+v", s)
	}
	if r.HasCommand() {
		t.Error("a download must not need the command confirmation")
	}
	if risks := r.Risky(); len(risks) != 1 || !strings.Contains(risks[0], "installs /usr/local/bin/node_exporter from https://example.com/") {
		t.Errorf("risks: %v", risks)
	}
	if got := StepName(Step{Type: "download", Path: "/opt/tool"}); got != "download /opt/tool" {
		t.Errorf("step name %q", got)
	}
	round := downloadRole(ToMarkdown(r.Steps))
	if err := round.Normalize(); err != nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if round.Hash() != (Role{Markdown: round.Markdown, Steps: r.Steps, Targets: r.Targets, Rollout: r.Rollout}).Hash() {
		t.Fatalf("round trip changed the download:\n%s\n%+v", round.Markdown, round.Steps)
	}

	plain := downloadRole("# Downloads\n- /opt/app.jar from https://example.com/app.jar\n  - sha256: " + sumA + "\n- remove /opt/old.jar\n")
	if err := plain.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s := plain.Steps[0]; s.Checksums[anyArch] != sumA || s.Owner != "root" || s.Group != "root" || s.Mode != "0644" {
		t.Fatalf("%+v", s)
	}
	if s := plain.Steps[1]; s.State != "absent" || s.Path != "/opt/old.jar" || !strings.Contains(ToMarkdown(plain.Steps), "- remove /opt/old.jar") {
		t.Fatalf("%+v", s)
	}
}

func TestDownloadRejects(t *testing.T) {
	item := func(head string, lines ...string) string {
		return "# Downloads\n- " + head + "\n" + strings.Join(lines, "\n") + "\n"
	}
	file, archive, sum := "/opt/tool from https://example.com/tool", "/opt/tool from https://example.com/tool.tar.gz", "  - sha256: "+sumA
	for name, tc := range map[string]struct{ md, want string }{
		"no checksum":        {item(file), "sha256 is required"},
		"short checksum":     {item(file, "  - sha256: abc123"), "64 hexadecimal"},
		"both forms":         {item(file, sum, "  - sha256 arm64: "+sumB), "either one sha256"},
		"unknown arch":       {item(file, "  - sha256 riscv64: "+sumA), "unknown download field"},
		"plain http":         {item("/opt/tool from http://example.com/tool", sum), "must be https://"},
		"token in address":   {item("/opt/tool from https://example.com/tool?token=abc", sum), "must be https://"},
		"password":           {item("/opt/tool from https://user:pass@example.com/tool", sum), "must be https://"},
		"shell in address":   {item("/opt/tool from https://example.com/$(id)", sum), "must be https://"},
		"relative path":      {item("tool from https://example.com/tool", sum), "path must be absolute"},
		"protected path":     {item("/proc/tool from https://example.com/tool", sum), "does not manage"},
		"no address":         {item("/opt/tool", sum), "write a download as"},
		"extract a file":     {item(file, sum, "  - extract: bin/tool"), "extract needs an address ending in"},
		"extract escapes":    {item(archive, sum, "  - extract: ../../etc/shadow"), "extract names one file"},
		"extract absolute":   {item(archive, sum, "  - extract: /etc/shadow"), "extract names one file"},
		"extract option":     {item(archive, sum, "  - extract: --to-command=id"), "extract names one file"},
		"extract wildcard":   {item(archive, sum, "  - extract: bin/*"), "extract names one file"},
		"bad mode":           {item(file, sum, "  - mode: rwx"), "mode an octal"},
		"bad owner":          {item(file, sum, "  - owner: root;id"), "owner and group must be account names"},
		"group twice":        {item(file, sum, "  - owner: app:apps", "  - group: web"), "group is set twice"},
		"unknown field":      {item(file, sum, "  - insecure: yes"), "unknown download field"},
		"field twice":        {item(file, sum, sum), "each download field once"},
		"removed with field": {item("remove /opt/tool", sum), "takes only its path"},
		"code block":         {item(file, sum, "", "  ```", "  x", "  ```"), "code blocks are only for"},
		"duplicate":          {item(file, sum) + "- " + file + "\n" + sum + "\n", "duplicate download"},
	} {
		r := downloadRole(tc.md)
		if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestDownloadArchitecture(t *testing.T) {
	s := Step{Type: "download", Path: "/opt/tool", URL: "https://example.com/tool", Checksums: map[string]string{"amd64": sumA}}
	if err := s.normalize(); err != nil {
		t.Fatal(err)
	}
	script, err := Script("tools", s, Host{Family: "apt", Arch: "amd64"}, true, false)
	if err != nil || !strings.Contains(script, "want='"+sumA+"'") {
		t.Fatalf("%v\n%s", err, script)
	}
	if _, err := Script("tools", s, Host{Family: "apt", Arch: "arm64"}, false, false); err == nil || !strings.Contains(err.Error(), "no sha256 for arm64 hosts") {
		t.Fatalf("an arm64 host got an amd64 checksum: %v", err)
	}
	// A plan reads the host and nothing else.
	plan, err := Script("tools", s, Host{Family: "apt", Arch: "amd64"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"mktemp", "curl -", "wget -", "install -d", "mv -f", "chown", "chmod"} {
		if strings.Contains(plan, forbidden) {
			t.Errorf("the plan script uses %q:\n%s", forbidden, plan)
		}
	}
}

// TestDownloadScript runs the generated scripts against a temporary
// directory, with a stand-in for the network.
func TestDownloadScript(t *testing.T) {
	for _, tool := range []string{"sha256sum", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	if out, err := exec.Command("stat", "-c", "%a", ".").CombinedOutput(); err != nil {
		t.Skipf("stat -c is not supported here: %s", out)
	}
	root, bin := t.TempDir(), t.TempDir()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"tool-1.0/bin/tool": "#!/bin/sh\necho tool 1.0\n", "tool-1.0/README": "read me\n"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	published := filepath.Join(root, "published")
	if err := os.WriteFile(published, archive.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	owner := strings.Fields(mustOutput(t, "stat", "-c", "%U %G", root))
	for name, body := range map[string]string{
		"curl":       "#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\ncp '" + published + "' \"$out\"\n",
		"chown":      "#!/bin/sh\nexit 0\n",
		"restorecon": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	sum := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
	step := func(path, sum, extract string) Step {
		s := Step{Type: "download", Path: path, URL: "https://example.com/tool-1.0.tar.gz", Checksums: map[string]string{anyArch: sum}, Extract: extract, Owner: owner[0], Group: owner[1], Mode: "0755"}
		if err := s.normalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	markers := filepath.Join(root, "markers")
	sh := func(s Step, apply bool) (string, error) {
		t.Helper()
		script, err := Script("tools", s, Host{Family: "apt"}, apply, false)
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", strings.ReplaceAll(script, "/var/lib/xela/downloads", markers)).CombinedOutput()
		return string(out), err
	}
	expect := func(s Step, apply bool, want string) {
		t.Helper()
		out, err := sh(s, apply)
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("got %v, want %q:\n%s", err, want, out)
		}
	}
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	leftovers := func(dir string) {
		t.Helper()
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".xela") {
				t.Errorf("temporary %s was left in %s", e.Name(), dir)
			}
		}
	}

	// One member of an archive.
	dest := filepath.Join(root, "opt/bin/tool")
	member := step(dest, sum, "tool-1.0/bin/tool")
	expect(member, false, "KORTA_RESULT changed would download https://example.com/tool-1.0.tar.gz (missing)")
	if exists(filepath.Dir(dest)) || exists(markers) {
		t.Fatal("the plan changed the host")
	}
	if out, err := sh(step(dest, sumA, "tool-1.0/bin/tool"), true); err == nil || !strings.Contains(out, "checksum mismatch") || !strings.Contains(out, sum) || exists(dest) {
		t.Fatalf("content with another checksum was installed: %v\n%s", err, out)
	}
	if out, err := sh(step(dest, sum, "tool-1.0/bin/missing"), true); err == nil || !strings.Contains(out, "could not be extracted") || !strings.Contains(out, "tool-1.0/README") || exists(dest) {
		t.Fatalf("a missing member was accepted: %v\n%s", err, out)
	}
	leftovers(filepath.Dir(dest))
	expect(member, true, "KORTA_RESULT changed installed from https://example.com/tool-1.0.tar.gz (missing; sha256 verified)")
	if body, _ := os.ReadFile(dest); string(body) != "#!/bin/sh\necho tool 1.0\n" {
		t.Fatalf("installed %q", body)
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0755 {
		t.Fatalf("mode %v", info.Mode())
	}
	leftovers(filepath.Dir(dest))
	expect(member, false, "KORTA_RESULT ok up to date")
	expect(member, true, "KORTA_RESULT ok up to date")

	os.Chmod(dest, 0700)
	expect(member, false, "KORTA_RESULT changed would fix owner or mode")
	expect(member, true, "KORTA_RESULT changed fixed owner or mode")
	expect(member, false, "KORTA_RESULT ok up to date")

	// A file changed on the host is noticed and replaced.
	os.WriteFile(dest, []byte("tampered\n"), 0755)
	expect(member, false, "(content differs)")
	expect(member, true, "(content differs; sha256 verified)")
	expect(member, false, "KORTA_RESULT ok up to date")

	// The downloaded file itself.
	whole := filepath.Join(root, "opt/tool.tar.gz")
	file := step(whole, sum, "")
	expect(file, true, "KORTA_RESULT changed installed from")
	if got, _ := os.ReadFile(whole); !bytes.Equal(got, archive.Bytes()) {
		t.Fatal("the downloaded file differs from the published one")
	}
	expect(file, false, "KORTA_RESULT ok up to date")

	removed := Step{Type: "download", Path: dest, State: "absent"}
	expect(removed, false, "KORTA_RESULT changed would remove")
	expect(removed, true, "KORTA_RESULT changed removed")
	if entries, _ := os.ReadDir(markers); exists(dest) || len(entries) != 0 {
		t.Fatal("removing left the file or its marker behind")
	}
	expect(removed, true, "KORTA_RESULT ok absent")
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
