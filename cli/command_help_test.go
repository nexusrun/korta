package cli

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func helpOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Help must not read credentials, request bodies or inventory files.
	args = append(args, "--config", filepath.Join(t.TempDir(), "missing", "config.json"), "--file", "/nonexistent/help-request")
	var out bytes.Buffer
	err := Run(context.Background(), args, strings.NewReader(""), &out, io.Discard)
	return out.String(), err
}

func TestScopedGroupHelp(t *testing.T) {
	for group, actions := range commands {
		t.Run(group, func(t *testing.T) {
			out, err := helpOutput(t, group, "--help")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, "Usage: korta "+group+" COMMAND") {
				t.Fatal(out)
			}
			for _, action := range actions {
				if !strings.Contains(out, "  "+action+" ") {
					t.Fatalf("missing %s: %s", action, out)
				}
			}
			for other := range commands {
				if other != group && strings.Contains(out, "korta "+other+" ") {
					t.Fatalf("unrelated %s help: %s", other, out)
				}
			}
			bare, err := helpOutput(t, group)
			if err != nil || bare != out {
				t.Fatalf("bare group differs: %v", err)
			}
		})
	}
}

func TestScopedActionHelp(t *testing.T) {
	for group, actions := range commands {
		for _, action := range actions {
			t.Run(group+"/"+action, func(t *testing.T) {
				out, err := helpOutput(t, group, action, "--help")
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out, "Usage: korta "+group+" "+action) || !strings.Contains(out, "Example:") {
					t.Fatal(out)
				}
				if strings.Contains(out, "Commands:") {
					t.Fatal("action displayed the group command list")
				}
				for other := range commands {
					if other != group && strings.Contains(out, "korta "+other+" ") {
						t.Fatalf("unrelated %s help: %s", other, out)
					}
				}
			})
		}
	}
}

func TestTopLevelHelpAndAliases(t *testing.T) {
	for _, command := range topLevel {
		out, err := helpOutput(t, command, "-h")
		if err != nil || !strings.Contains(out, "Usage: korta "+command) {
			t.Fatalf("%s: %s %v", command, out, err)
		}
		if (command == "plan" || command == "apply" || command == "inventory") && strings.Contains(out, "--token-file") {
			t.Fatalf("offline help includes manager credentials: %s", out)
		}
	}
	out, err := helpOutput(t, "--help")
	if err != nil || out != help {
		t.Fatalf("root help changed: %v", err)
	}
	for _, args := range [][]string{{"ssh-keys", "--help"}, {"ssh-keys", "create", "--help"}, {"--help", "instances"}, {"instances", "-h"}, {"instances", "create", "db1", "--help"}} {
		if _, err := helpOutput(t, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"missing", "--help"}, {"instances", "missing", "--help"}} {
		if _, err := helpOutput(t, args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestCreateHelpShowsRelevantFlags(t *testing.T) {
	for group, flags := range map[string][]string{"instances": {"--host HOST", "--user USER", "--key KEY_ID"}, "roles": {"--markdown FILE", "--instance ID", "--label KEY=VALUE"}, "deployments": {"--type TYPE", "--instance ID"}, "keys": {"--private-key FILE"}} {
		out, err := helpOutput(t, group, "create", "--help")
		if err != nil {
			t.Fatal(err)
		}
		for _, flag := range flags {
			if !strings.Contains(out, flag) {
				t.Errorf("%s missing %s", group, flag)
			}
		}
	}
}

func TestOfflineHelpShowsVariablesAndKeys(t *testing.T) {
	for _, command := range []string{"plan", "apply"} {
		out, err := helpOutput(t, command, "--help")
		if err != nil || !strings.Contains(out, "--var NAME=VALUE") || !strings.Contains(out, "-k, --identity FILE") {
			t.Fatalf("%s: %s %v", command, out, err)
		}
	}
	out, _ := helpOutput(t, "roles", "create", "--help")
	if !strings.Contains(out, "Template files named with from are sent along") {
		t.Fatal(out)
	}
}

func TestNameFlagForCreate(t *testing.T) {
	for args, want := range map[string]string{
		"instances create --name db1 --host 10.0.0.5 --user ubuntu --key key_1": `"name":"db1"`,
		"deployments create --name orders --type postgres --instance ins_1":     `"name":"orders"`,
	} {
		o, _ := parse(strings.Fields(args))
		c := client{opts: o, in: strings.NewReader("")}
		_, _, body, err := c.route()
		if err != nil || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %s %v", args, body, err)
		}
	}
}
