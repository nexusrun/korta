package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"

	"encoding/json"
	"errors"
	"golang.org/x/crypto/ssh"

	"github.com/nexusrun/korta/internal/awsprovider/cloudtest"
	"github.com/nexusrun/korta/roles"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const awsRoleMarkdown = `# AWS instance
- name: web
- region: us-east-1
- image: ami-12345678
- subnet: subnet-12345678
- security-groups: sg-12345678
- key-pair: deploy
- ssh-key: key_test

# Packages
- nginx
`

func TestAWSRoleCreateNeedsNoExistingTargets(t *testing.T) {
	o, err := parse([]string{"roles", "create", "--name", "web", "--file", "-"})
	if err != nil {
		t.Fatal(err)
	}
	c := client{opts: o, in: strings.NewReader(awsRoleMarkdown)}
	method, path, body, err := c.route()
	if err != nil || method != "POST" || path != "/api/roles" {
		t.Fatalf("%s %s %v", method, path, err)
	}
	var r struct{ Name, Markdown string }
	if err := json.Unmarshal(body, &r); err != nil || r.Markdown != awsRoleMarkdown || r.Name != "web" {
		t.Fatalf("%s %v", body, err)
	}
}

func TestAWSOfflineRefusesBeforeRequiringInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aws.md")
	if err := os.WriteFile(path, []byte(awsRoleMarkdown), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"plan", "apply"} {
		_, _, err := runLocal(t, cmd, path)
		if err == nil || !strings.Contains(err.Error(), "do not yet support") {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
}

func TestAWSPlanAndLaunchRecovery(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "role.md")
	if err := os.WriteFile(path, []byte("# AWS instance\n- name: web\n- region: us-east-1\n\n# Packages\n- nginx\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &cloudtest.Fake{LaunchErr: errors.New("lost launch response")}
	run := func(cmd string) error {
		args := []string{cmd, path}
		if cmd == "apply" {
			args = append(args, "--yes")
		}
		opts, err := parse(args)
		if err != nil {
			return err
		}
		c := client{opts: opts, in: strings.NewReader(""), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, aws: fake}
		return c.local(context.Background())
	}
	if err := run("plan"); err != nil {
		t.Fatal(err)
	}
	dir, err := awsStateDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("plan wrote state: %v", err)
	}
	if err := run("apply"); err == nil {
		t.Fatal("expected launch failure")
	}
	state, err := readAWSState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.Reservations["web"].Token == "" || state.Reservations["web"].InstanceID != "" {
		t.Fatalf("reservation: %+v", state.Reservations["web"])
	}
	if err := run("apply"); err == nil {
		t.Fatal("expected launch failure")
	}
	if len(fake.Launched) != 1 || len(fake.Tokens) != 2 || fake.Tokens[0] != fake.Tokens[1] {
		t.Fatalf("launches: %d, tokens: %v", len(fake.Launched), fake.Tokens)
	}
}

func TestAWSStateRejectsScaleDownAndChanges(t *testing.T) {
	spec := roles.AWSInstance{Name: "web", Count: 2}
	state := awsLocalState{Version: 1, OwnerID: "role_123", Account: "123456789012", Spec: spec, Reservations: map[string]awsReservation{"web": {Token: "t1", Spec: roles.AWSInstance{Name: "web", Image: "ami-1", Subnet: "subnet-1"}}, "web-2": {Token: "t2", Spec: roles.AWSInstance{Name: "web-2", Image: "ami-1", Subnet: "subnet-1"}}}}
	smaller := spec
	smaller.Count = 1
	if err := checkAWSSpec(state, smaller); err == nil {
		t.Fatal("allowed scale down")
	}
	larger := spec
	larger.Count = 3
	if err := checkAWSSpec(state, larger); err != nil {
		t.Fatal(err)
	}
	larger.Region = "us-east-1"
	if err := checkAWSSpec(state, larger); err == nil {
		t.Fatal("allowed changed launch settings")
	}
}

func TestAWSApplyProvisionsAndConfiguresOnlyOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "role.md")
	if err := os.WriteFile(path, []byte("# AWS instance\n- name: web\n- region: us-east-1\n\n# Packages\n- nginx\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	fake := &cloudtest.Fake{}
	configured := 0
	scans := 0
	run := func() error {
		opts, err := parse([]string{"apply", path, "--yes"})
		if err != nil {
			return err
		}
		c := client{opts: opts, in: strings.NewReader(""), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, aws: fake,
			awsScan: func(context.Context, string) (string, error) { scans++; return hostKey, nil },
			awsConfigure: func(_ context.Context, _ *localRole, res awsReservation, name, private, dir string) error {
				configured++
				if name != "web" || res.InstanceID == "" || private == "" || res.HostKey != hostKey {
					t.Errorf("bad host: %+v", res)
				}
				return nil
			},
		}
		return c.local(context.Background())
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if len(fake.Launched) != 1 || scans != 1 || configured != 2 {
		t.Fatalf("launches %d, scans %d, configurations %d", len(fake.Launched), scans, configured)
	}
}
