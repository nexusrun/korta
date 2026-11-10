package roles

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const dockerFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

func repositoryRole(body string) Role {
	return Role{Name: "docker", Markdown: body, Targets: Targets{InstanceIDs: []string{"host"}}}
}

func TestRepositoryMarkdown(t *testing.T) {
	md := "# Package repositories\n- docker\n  - url: https://download.docker.com/linux/{{ os.distro }}/\n  - key: `https://download.docker.com/linux/ubuntu/gpg`\n  - fingerprint: 9dc8 5822 9fc7 dd38 854a  e2d8 8d81 803c 0ebf cd88\n  - components: stable\n\n# Packages\n- docker-ce\n"
	r := repositoryRole(md)
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	s := r.Steps[0]
	if len(r.Steps) != 2 || s.Type != "repository" || s.Repository != "docker" || s.State != "present" ||
		s.URL != "https://download.docker.com/linux/ubuntu" || s.KeyURL != "https://download.docker.com/linux/ubuntu/gpg" ||
		len(s.Fingerprints) != 1 || s.Fingerprints[0] != dockerFingerprint || strings.Join(s.Components, ",") != "stable" {
		t.Fatalf("%+v", r.Steps)
	}
	if r.HasCommand() {
		t.Error("a repository must not need the command confirmation")
	}
	if risks := r.Risky(); len(risks) != 1 || !strings.Contains(risks[0], "trusts the package repository https://download.docker.com/linux/ubuntu") {
		t.Errorf("risks: %v", risks)
	}
	if got := StepName(Step{Type: "repository", Repository: "docker"}); got != "repository docker" {
		t.Errorf("step name %q", got)
	}
	round := repositoryRole(ToMarkdown(r.Steps))
	if err := round.Normalize(); err != nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if round.Hash() == "" || round.Steps[0].URL != s.URL || round.Steps[0].Fingerprints[0] != dockerFingerprint || round.Steps[0].Components[0] != "stable" {
		t.Fatalf("round trip changed the repository:\n%s", round.Markdown)
	}

	removed := repositoryRole("# Repositories\n- remove docker\n")
	if err := removed.Normalize(); err != nil {
		t.Fatal(err)
	}
	if removed.Steps[0].State != "absent" || len(removed.Risky()) != 0 || !strings.Contains(ToMarkdown(removed.Steps), "- remove docker") {
		t.Fatalf("%+v", removed.Steps)
	}
}

func TestRepositoryRejects(t *testing.T) {
	field := func(lines ...string) string {
		return "# Repositories\n- docker\n" + strings.Join(lines, "\n") + "\n"
	}
	url, key, fpr := "  - url: https://example.com/apt", "  - key: https://example.com/key.asc", "  - fingerprint: "+dockerFingerprint
	for name, tc := range map[string]struct{ md, want string }{
		"no fingerprint":   {field(url, key), "fingerprint is required"},
		"short key ID":     {field(url, key, "  - fingerprint: 0EBFCD88"), "full 40 hexadecimal"},
		"same fingerprint": {field(url, key, fpr+", "+dockerFingerprint), "listed twice"},
		"plain http":       {field("  - url: http://example.com/apt", key, fpr), "url must be an https://"},
		"password in url":  {field("  - url: https://user:pass@example.com/apt", key, fpr), "url must be an https://"},
		"shell in url":     {field("  - url: https://example.com/$(id)", key, fpr), "url must be an https://"},
		"unknown variable": {field("  - url: https://example.com/$HOME", key, fpr), "url must be an https://"},
		"quote in url":     {field("  - url: https://example.com/a'b", key, fpr), "url must be an https://"},
		"no key":           {field(url, fpr), "key must be the https://"},
		"http key":         {field(url, "  - key: http://example.com/key.asc", fpr), "key must be the https://"},
		"variable in key":  {field(url, "  - key: https://example.com/$releasever/key", fpr), "key must be the https://"},
		"bad suite":        {field(url, key, fpr, "  - suite: noble;id"), "invalid suite"},
		"bad component":    {field(url, key, fpr, "  - components: main, a/b"), "invalid component"},
		"unknown field":    {field(url, key, fpr, "  - gpgcheck: 0"), "unknown repository field"},
		"field twice":      {field(url, url, key, fpr), "each repository field once"},
		"bad name":         {"# Repositories\n- Docker_CE\n" + url + "\n" + key + "\n" + fpr + "\n", "lowercase name"},
		"two names":        {"# Repositories\n- docker ce\n", "write the repository's name"},
		"removed with url": {"# Repositories\n- remove docker\n" + url + "\n", "takes only its name"},
		"code block":       {"# Repositories\n- docker\n\n  ```\n  deb https://example.com\n  ```\n", "code blocks are only for"},
		"duplicate":        {field(url, key, fpr) + "- docker\n" + url + "\n" + key + "\n" + fpr + "\n", "duplicate repository"},
		"too many keys":    {field(url, key, "  - fingerprint: "+strings.TrimSuffix(strings.Repeat(dockerFingerprint+", ", 9), ", ")), "1-8 signing key fingerprints"},
	} {
		r := repositoryRole(tc.md)
		if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestRepositoryHeadings(t *testing.T) {
	for heading, want := range map[string]string{
		"Repositories": "repository", "Package repositories": "repository", "Software repository": "repository", "Add the Docker repository": "repository",
		"Packages": "packages", "Packages from the vendor repository": "packages", "Files for the repository": "file",
	} {
		if got := headingKind(heading); got != want {
			t.Errorf("%q manages %q, want %q", heading, got, want)
		}
	}
}

func TestRepositoryHostFamily(t *testing.T) {
	dnf := Step{Type: "repository", Repository: "docker", State: "present", URL: "https://download.docker.com/linux/rhel/$releasever/$basearch/stable", KeyURL: "https://download.docker.com/linux/rhel/gpg", Fingerprints: []string{dockerFingerprint}}
	if err := dnf.normalize(); err != nil {
		t.Fatal(err)
	}
	apt := Step{Type: "repository", Repository: "docker", State: "present", URL: "https://download.docker.com/linux/ubuntu", KeyURL: "https://download.docker.com/linux/ubuntu/gpg", Fingerprints: []string{dockerFingerprint}, Suite: "noble"}
	for _, tc := range []struct {
		name   string
		step   Step
		family string
		want   string // an error, or text the script must contain
		fails  bool
	}{
		{"dnf variables on dnf", dnf, "rpm", "baseurl=$repo_url", false},
		{"dnf variables on apt", dnf, "apt", "dnf variables", true},
		{"suite on apt", apt, "apt", "suite='noble'", false},
		{"suite on dnf", apt, "rpm", "for apt hosts", true},
	} {
		script, err := Script("docker", tc.step, Host{Family: tc.family}, true, false)
		switch {
		case tc.fails && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want an error containing %q", tc.name, err, tc.want)
		case !tc.fails && (err != nil || !strings.Contains(script, tc.want)):
			t.Errorf("%s: %v\n%s", tc.name, err, script)
		}
	}
	removed := Step{Type: "repository", Repository: "docker", State: "absent"}
	if _, err := Script("docker", removed, Host{Family: "apt"}, true, false); err != nil {
		t.Error(err)
	}
	// A plan reads the host and nothing else.
	plan, err := Script("docker", apt, Host{Family: "apt"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"mktemp", "curl -", "wget -", "apt-get", "gpg --"} {
		if strings.Contains(plan, forbidden) {
			t.Errorf("the plan script uses %q:\n%s", forbidden, plan)
		}
	}
}

// TestRepositoryScript runs the generated scripts against a fake host
// directory, with stand-ins for the network and the package manager.
func TestRepositoryScript(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed")
	}
	root, bin, home := t.TempDir(), t.TempDir(), t.TempDir()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	run("gpg", "--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "Korta Test <test@example.invalid>", "ed25519", "sign", "never")
	fingerprint := ""
	for _, line := range strings.Split(run("gpg", "--batch", "--homedir", home, "--list-keys", "--with-colons"), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" && fingerprint == "" {
			fingerprint = f[9]
		}
	}
	keyFile := filepath.Join(root, "published.asc")
	if err := os.WriteFile(keyFile, []byte(run("gpg", "--batch", "--homedir", home, "--armor", "--export")), 0644); err != nil {
		t.Fatal(err)
	}
	refresh := filepath.Join(root, "refresh-fails")
	for name, body := range map[string]string{
		"curl":       "#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\ncp '" + keyFile + "' \"$out\"\n",
		"apt-get":    "#!/bin/sh\nif [ -e '" + refresh + "' ]; then echo 'E: The repository does not have a Release file.'; exit 100; fi\n",
		"restorecon": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	list, key := filepath.Join(root, "apt/sources.list.d/xela-test.sources"), filepath.Join(root, "apt/keyrings/xela-test.gpg")
	step := func(fpr, url string) Step {
		s := Step{Type: "repository", Repository: "test", URL: url, KeyURL: "https://example.com/key.asc", Fingerprints: []string{fpr}, Suite: "stable"}
		if err := s.normalize(); err != nil {
			t.Fatal(err)
		}
		return s
	}
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	sh := func(s Step, apply bool) (string, error) {
		t.Helper()
		script, err := Script("web", s, Host{Family: "apt"}, apply, false)
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", strings.ReplaceAll(script, "/etc/apt", filepath.Join(root, "apt"))).CombinedOutput()
		return string(out), err
	}
	expect := func(s Step, apply bool, want string) {
		t.Helper()
		out, err := sh(s, apply)
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("got %v, want %q:\n%s", err, want, out)
		}
	}
	good := step(fingerprint, "https://example.com/apt")

	expect(good, false, "KORTA_RESULT changed would add https://example.com/apt")
	if exists(list) || exists(key) {
		t.Fatal("the plan changed the host")
	}

	if out, err := sh(step(dockerFingerprint, "https://example.com/apt"), true); err == nil || !strings.Contains(out, "signing key mismatch") || !strings.Contains(out, fingerprint) {
		t.Fatalf("a key with another fingerprint was accepted: %v\n%s", err, out)
	}
	if exists(list) || exists(key) {
		t.Fatal("a refused key left files behind")
	}

	expect(good, true, "KORTA_RESULT changed added https://example.com/apt; signing key verified")
	content, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Managed by Xela role web", "# Key: " + fingerprint, "Types: deb", "URIs: https://example.com/apt", "Suites: stable", "Components: main", "Signed-By: " + key} {
		if !strings.Contains(string(content), want+"\n") {
			t.Errorf("the list file lacks %q:\n%s", want, content)
		}
	}
	if installed := run("gpg", "--batch", "--homedir", t.TempDir(), "--show-keys", "--with-colons", key); !strings.Contains(installed, fingerprint) {
		t.Errorf("the installed key is not the verified one:\n%s", installed)
	}
	expect(good, false, "KORTA_RESULT ok configured")
	expect(good, true, "KORTA_RESULT ok configured")

	// A repository that cannot be read is rolled back to the working one.
	if err := os.WriteFile(refresh, nil, 0644); err != nil {
		t.Fatal(err)
	}
	moved := step(fingerprint, "https://example.com/moved")
	expect(moved, false, "KORTA_RESULT changed would update https://example.com/moved")
	if out, err := sh(moved, true); err == nil || !strings.Contains(out, "does not have a Release file") || !strings.Contains(out, "previous configuration was put back") {
		t.Fatalf("an unreadable repository was kept: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(list); string(after) != string(content) {
		t.Fatalf("the previous list file was not put back:\n%s", after)
	}
	os.Remove(refresh)
	expect(moved, true, "KORTA_RESULT changed updated https://example.com/moved")

	removed := Step{Type: "repository", Repository: "test", State: "absent"}
	expect(removed, false, "KORTA_RESULT changed would remove")
	expect(removed, true, "KORTA_RESULT changed removed")
	if exists(list) || exists(key) {
		t.Fatal("removing left files behind")
	}
	expect(removed, true, "KORTA_RESULT ok absent")
}
