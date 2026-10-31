package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleMarkdownInputs(t *testing.T) {
	md := "# Packages\n- nginx\n"
	file := filepath.Join(t.TempDir(), "extensionless")
	if err := os.WriteFile(file, []byte(md), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]string{{"--file", file}, {"--markdown", file}, {"--file", "-"}, {"--markdown", "-"}} {
		args := append([]string{"roles", "create", "--name", "cli-test-role", "--instance", "ins_1", "--instance", "ins_2,ins_3", "--label", "env=prod", "--label", "team=web", "--batch-size", "2"}, input...)
		o, err := parse(args)
		if err != nil {
			t.Fatal(err)
		}
		c := client{opts: o, in: strings.NewReader(md)}
		method, path, b, err := c.route()
		if err != nil {
			t.Fatal(err)
		}
		var r struct {
			Name, Markdown string
			Targets        struct {
				InstanceIDs []string
				Labels      map[string]string
			}
			Rollout struct{ BatchSize int }
		}
		if err = json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		if method != "POST" || path != "/api/roles" || r.Name != "cli-test-role" || r.Markdown != md || len(r.Targets.InstanceIDs) != 3 || r.Targets.Labels["team"] != "web" || r.Rollout.BatchSize != 2 {
			t.Fatalf("%s %s %s", method, path, b)
		}
	}
	for _, args := range [][]string{{"roles", "preview", "--file", file}, {"roles", "preview", "--markdown", file}} {
		o, _ := parse(args)
		c := client{opts: o}
		_, _, b, err := c.route()
		if err != nil || !strings.Contains(string(b), "markdown") {
			t.Fatalf("%s %v", b, err)
		}
	}
	for _, args := range [][]string{{"roles", "create", "--file", file}, {"roles", "create", "--file", file, "--markdown", file}, {"roles", "create", "--file", file, "--name", "test", "--label", "bad"}, {"roles", "create", "--file", file, "--name", "test", "--batch-size", "0"}} {
		o, _ := parse(args)
		c := client{opts: o}
		if _, _, _, err := c.route(); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestMarkdownFromStdinKeepsNewlines(t *testing.T) {
	o, _ := parse([]string{"roles", "create", "--file", "-", "--name", "stdin-role", "--label", "env=prod"})
	c := client{opts: o, in: strings.NewReader("# Packages\n- curl\n")}
	_, _, b, err := c.route()
	if err != nil || !strings.Contains(string(b), `\n`) {
		t.Fatalf("newlines lost: %s %v", b, err)
	}
}
