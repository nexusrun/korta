package cli

import (
	"encoding/json"
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
		if err == nil || !strings.Contains(err.Error(), "Enterprise manager") {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
}
