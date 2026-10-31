package roles

import (
	"reflect"
	"strings"
	"testing"
)

func network(t *testing.T, md string) (*AWSNetwork, error) {
	t.Helper()
	r := Role{Name: "prod-network", Markdown: md}
	if err := r.Normalize(); err != nil {
		return nil, err
	}
	return r.AWSNetwork(), nil
}

func TestAWSNetworkDefaults(t *testing.T) {
	n, err := network(t, "# AWS network\n- name: prod\n")
	if err != nil {
		t.Fatal(err)
	}
	if n.CIDR != "10.0.0.0/16" || n.Zones != 2 || n.NAT != "one" || n.NATGateways() != 1 || n.VPC != "" {
		t.Fatalf("%+v", n)
	}
	n, err = network(t, "# AWS VPC\n- name: prod\n- region: eu-west-1\n- cidr: 10.20.5.0/16\n- zones: 3\n- nat: per-zone\n- ssh from: 10.8.0.1/24\n")
	if err != nil || n.CIDR != "10.20.0.0/16" || n.NATGateways() != 3 || n.SSHFrom[0] != "10.8.0.0/24" {
		t.Fatalf("%+v %v", n, err)
	}
	r := Role{Name: "net", Markdown: "# AWS network\n- name: prod\n- zones: 3\n- nat: per-zone\n"}
	if err := r.Normalize(); err != nil || !strings.Contains(strings.Join(r.Risky(), ";"), "3 NAT gateways") {
		t.Fatal(err, r.Risky())
	}
	md := ToMarkdown(r.Steps)
	round := Role{Name: "net", Markdown: md}
	if err := round.Normalize(); err != nil || !reflect.DeepEqual(round.AWSNetwork(), r.AWSNetwork()) {
		t.Fatalf("%s %v", md, err)
	}
}

func TestAWSNetworkAdopt(t *testing.T) {
	n, err := network(t, "# AWS network\n- name: legacy\n- vpc: vpc-0123456789abcdef0\n- public subnets: subnet-0123456789abcdef0, subnet-0fedcba9876543210\n- private subnets: 10.1.10.0/24, 10.1.11.0/24\n")
	if err != nil {
		t.Fatal(err)
	}
	if n.CIDR != "" || n.Zones != 2 || n.PublicSubnets[0] != "subnet-0123456789abcdef0" || n.PrivateSubnets[1] != "10.1.11.0/24" {
		t.Fatalf("%+v", n)
	}
	r := Role{Name: "legacy", Markdown: "# AWS network\n- name: legacy\n- vpc: vpc-0123456789abcdef0\n"}
	if err := r.Normalize(); err != nil || !strings.Contains(r.Risky()[0], "adds Korta's subnets and routes to VPC") {
		t.Fatal(err, r.Risky())
	}
}

func TestAWSNetworkRejects(t *testing.T) {
	for name, md := range map[string]string{
		"both":        "- vpc: vpc-0123456789abcdef0\n- cidr: 10.0.0.0/16\n",
		"wide":        "- cidr: 10.0.0.0/8\n",
		"outside":     "- cidr: 10.0.0.0/16\n- public subnets: 10.1.0.0/24, 10.1.1.0/24\n",
		"overlap":     "- public subnets: 10.0.0.0/24, 10.0.0.128/25\n",
		"per-zone":    "- zones: 3\n- public subnets: 10.0.0.0/24, 10.0.1.0/24\n",
		"id-new":      "- public subnets: subnet-0123456789abcdef0, subnet-0fedcba9876543210\n",
		"nat-public":  "- public subnets: none\n- nat: one\n",
		"no-subnets":  "- public subnets: none\n- private subnets: none\n",
		"zones":       "- zones: 7\n",
		"variable":    "- cidr: {{ cidr }}\n",
		"unknown":     "- igw: yes\n",
		"bad-account": "- account: Prod Account\n",
	} {
		if _, err := network(t, "# AWS network\n- name: prod\n"+md); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, md := range map[string]string{
		"with-config":   "# AWS network\n- name: prod\n\n# Packages\n- nginx\n",
		"with-instance": "# AWS instance\n- name: web\n\n# AWS network\n- name: prod\n",
	} {
		if _, err := network(t, md); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if aws, err := ProvisionsAWS("# AWS network\n- name: prod\n"); !aws || err != nil {
		t.Fatal(aws, err)
	}
}
