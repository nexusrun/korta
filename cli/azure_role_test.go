package cli

import (
	"strings"
	"testing"
)

func TestAzureRoleCreateNeedsNoTargets(t *testing.T) {
	md := "# Azure instance\n- name: web\n- subscription: 12345678-1234-1234-1234-123456789abc\n- resource-group: rg\n- location: eastus\n- virtual-network: vnet\n- subnet: app\n"
	opts, err := parse([]string{"roles", "create", "--name", "azure-web", "--file", "-"})
	if err != nil {
		t.Fatal(err)
	}
	c := client{opts: opts, in: strings.NewReader(md)}
	method, path, _, err := c.route()
	if err != nil || method != "POST" || path != "/api/roles" {
		t.Fatalf("%s %s %v", method, path, err)
	}
}

func TestAzureNetworkRoleCreateNeedsNoTargets(t *testing.T) {
	md := "# Azure network\n- name: prod\n- resource-group: rg\n- location: eastus\n"
	opts, err := parse([]string{"roles", "create", "--name", "prod-network", "--file", "-"})
	if err != nil {
		t.Fatal(err)
	}
	c := client{opts: opts, in: strings.NewReader(md)}
	if method, path, _, err := c.route(); err != nil || method != "POST" || path != "/api/roles" {
		t.Fatalf("%s %s %v", method, path, err)
	}
}
