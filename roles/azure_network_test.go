package roles

import (
	"reflect"
	"strings"
	"testing"
)

func azureNetwork(md string) (*AzureNetwork, error) {
	r := Role{Name: "prod-network", Markdown: md}
	if err := r.Normalize(); err != nil {
		return nil, err
	}
	return r.AzureNetwork(), nil
}

func TestAzureNetworkDefaults(t *testing.T) {
	n, err := azureNetwork("# Azure network\n- name: prod\n- resource-group: production\n- location: eastus\n")
	if err != nil {
		t.Fatal(err)
	}
	want := AzureNetwork{Name: "prod", ResourceGroup: "production", Location: "eastus", AddressSpace: "10.0.0.0/16", Subnets: []AzureSubnet{{"app", "10.0.0.0/24"}}}
	if !reflect.DeepEqual(*n, want) {
		t.Fatalf("%+v", n)
	}
	md := "# Azure virtual network\n- name: prod\n- subscription: 12345678-1234-1234-1234-123456789abc\n- resource group: production\n- location: eastus\n- address-space: 10.10.5.0/16\n- subnets: app 10.10.1.0/24, db=10.10.2.9/24\n- ssh from: 203.0.113.7, 10.8.0.1/24\n"
	n, err = azureNetwork(md)
	if err != nil || n.AddressSpace != "10.10.0.0/16" || n.Subnets[1] != (AzureSubnet{"db", "10.10.2.0/24"}) || !reflect.DeepEqual(n.SSHFrom, []string{"203.0.113.7/32", "10.8.0.0/24"}) {
		t.Fatalf("%+v %v", n, err)
	}
	r := Role{Name: "net", Markdown: md}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	round := Role{Name: "net", Markdown: ToMarkdown(r.Steps)}
	if err := round.Normalize(); err != nil || !reflect.DeepEqual(round.AzureNetwork(), r.AzureNetwork()) {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	if !strings.Contains(strings.Join(r.Risky(), " "), "virtual network prod with 2 subnets") {
		t.Fatal(r.Risky())
	}
	if ok, err := ProvisionsAzure(md); !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestAzureNetworkRejects(t *testing.T) {
	base := "# Azure network\n- name: prod\n- resource-group: production\n- location: eastus\n"
	for name, md := range map[string]string{
		"missing group":     "# Azure network\n- name: prod\n- location: eastus\n",
		"bad name":          strings.Replace(base, "prod", "Prod_1", 1),
		"outside space":     base + "- address-space: 10.10.0.0/16\n- subnets: app 10.20.1.0/24\n",
		"overlap":           base + "- subnets: app 10.0.0.0/24, db 10.0.0.128/25\n",
		"duplicate subnet":  base + "- subnets: app 10.0.0.0/24, APP 10.0.1.0/24\n",
		"reserved subnet":   base + "- subnets: GatewaySubnet 10.0.0.0/24\n",
		"too small":         base + "- subnets: app 10.0.0.0/30\n",
		"bad pair":          base + "- subnets: app\n",
		"ssh":               base + "- ssh from: anywhere\n",
		"variable":          base + "- address-space: {{vars.space}}\n",
		"unknown field":     base + "- nat: one\n",
		"other section":     base + "\n# Packages\n- nginx\n",
		"with instance":     base + "\n# Azure instance\n- name: web\n- network: prod\n",
		"with other cloud":  base + "\n# AWS instance\n- name: web\n",
		"no bullets":        "# Azure network\n",
		"bad subscription":  base + "- subscription: nope\n",
		"targets via label": "",
	} {
		if md == "" {
			r := Role{Name: "net", Markdown: base, Targets: Targets{Labels: map[string]string{"env": "prod"}}}
			if err := r.Normalize(); err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if _, err := azureNetwork(md); err == nil {
			t.Errorf("%s: accepted\n%s", name, md)
		}
	}
}

func TestAzureInstanceInNetwork(t *testing.T) {
	md := "# Azure instance\n- name: web\n- network: prod\n- count: 2\n- image: Canonical:ubuntu-24_04-lts:server:24.04.202610210\n\n# Packages\n- nginx\n"
	r := Role{Name: "web", Markdown: md}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a := r.Azure(); a.Network != "prod" || a.Subnet != "" || a.Count != 2 || a.Address != "public" {
		t.Fatalf("%+v", a)
	}
	round := Role{Name: "web", Markdown: ToMarkdown(r.Steps)}
	if err := round.Normalize(); err != nil || round.Azure().Network != "prod" {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	for _, extra := range []string{"- resource-group: rg\n", "- virtual-network: vnet\n", "- network-interface: nic\n", "- location: eastus\n", "- subscription: 12345678-1234-1234-1234-123456789abc\n"} {
		bad := Role{Name: "web", Markdown: strings.Replace(md, "- count: 2\n", extra, 1)}
		if err := bad.Normalize(); err == nil || !strings.Contains(err.Error(), "network prod supplies") {
			t.Errorf("%q: %v", extra, err)
		}
	}
}
