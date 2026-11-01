package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyBinaryAndDryRun(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	captured := filepath.Join(dir, "captured")
	fake := `#!/bin/sh
case "$*" in
 *mktemp*) cat > "$COPY_CAPTURE" ;;
 *) echo missing ;;
esac
`
	if err := os.WriteFile(ssh, []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("COPY_CAPTURE", captured)
	inv := filepath.Join(dir, "hosts.md")
	if err := os.WriteFile(inv, []byte("# Staging\n- web1 192.0.2.1 env=staging\n- web2 192.0.2.2 env=other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "source")
	data := []byte{0, 1, 2, 255, 'x', '\n'}
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(flags ...string) (string, error) {
		var out bytes.Buffer
		args := []string{"copy", src, "/etc/app.conf", "-i", inv, "--limit", "env=staging", "--json"}
		args = append(args, flags...)
		err := Run(context.Background(), args, strings.NewReader(""), &out, io.Discard)
		return out.String(), err
	}
	out, err := run("--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(captured); !os.IsNotExist(err) {
		t.Fatal("dry run copied data")
	}
	var rows []copyResult
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 || rows[0].Status != "would change" {
		t.Fatalf("%s: %v", out, err)
	}
	out, err = run("--yes")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || rows[0].Status != "copied" {
		t.Fatalf("%s: %v", out, err)
	}
	got, err := os.ReadFile(captured)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("binary bytes changed: %x %v", got, err)
	}
}

func TestCopyRejectsUnsafeInputs(t *testing.T) {
	for _, dest := range []string{"relative", "/etc/../proc/x", "/dev/x", "/tmp//x", "/tmp/"} {
		var out bytes.Buffer
		err := Run(context.Background(), []string{"copy", "missing", dest}, strings.NewReader(""), &out, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "destination") {
			t.Fatalf("%s: %v", dest, err)
		}
	}
}

// The fake SSH transport executes the actual generated shell against files in
// a temporary directory. Stub only platform-specific ownership and stat.
func TestCopyExecutesAtomicShellAndConverges(t *testing.T) {
	dir := t.TempDir()
	scripts := map[string]string{
		"ssh":        "#!/bin/sh\nfor last do :; done\nexec /bin/sh -c \"$last\"\n",
		"id":         "#!/bin/sh\nprintf '0\\n'\n",
		"chown":      "#!/bin/sh\nexit 0\n",
		"stat":       "#!/bin/sh\nprintf '644 root root\\n'\n",
		"restorecon": "#!/bin/sh\nexit 0\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv := filepath.Join(dir, "hosts.md")
	if err := os.WriteFile(inv, []byte("# Hosts\n- host 192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	src, dest := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	data := []byte{0, 255, 13, 10, 42}
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	run := func() (string, error) {
		var out bytes.Buffer
		err := Run(context.Background(), []string{"copy", src, dest, "-i", inv, "--yes", "--json"}, strings.NewReader(""), &out, io.Discard)
		return out.String(), err
	}
	out, err := run()
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("copied %x: %v", got, err)
	}
	out, err = run()
	if err != nil || !strings.Contains(out, `"status": "unchanged"`) {
		t.Fatalf("second copy: %s %v", out, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".korta-copy.*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v %v", matches, err)
	}
}
