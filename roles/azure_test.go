package roles

import (
	"strings"
	"testing"
)

func TestAzureRole(t *testing.T) {
	md := "# Azure instance\n- name: web\n- subscription: 12345678-1234-1234-1234-123456789abc\n- resource-group: production\n- location: eastus\n- virtual-network: app-vnet\n- subnet: app\n\n# Packages\n- nginx\n"
	role := Role{Name: "web", Markdown: md}
	if err := role.Normalize(); err != nil {
		t.Fatal(err)
	}
	if role.Azure() == nil || role.Azure().Size != "Standard_B2s" || len(role.Steps) != 2 {
		t.Fatalf("%+v", role)
	}
	round := Role{Name: "web", Markdown: ToMarkdown(role.Steps)}
	if err := round.Normalize(); err != nil || round.Azure() == nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if !strings.Contains(strings.Join(role.Risky(), " "), "billable") {
		t.Fatal(role.Risky())
	}
	for _, bad := range []string{strings.Replace(md, "eastus", "{{secret.region}}", 1), strings.Replace(md, "app-vnet", "../evil", 1), md + "\n# Azure instance\n- user: admin\n", md + "\n# AWS instance\n- name: other\n"} {
		r := Role{Name: "web", Markdown: bad}
		if err := r.Normalize(); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
