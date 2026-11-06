package roles

import (
	"fmt"
	"net/netip"
	"strings"
)

// AzureNetwork describes a virtual network that Korta creates in an existing
// resource group, with its subnets and a network security group that allows
// SSH. Azure instance roles place VMs in it with "network: NAME". Korta never
// adopts or changes a virtual network it did not create.
type AzureNetwork struct {
	Name          string        `json:"name"`                   // also the virtual network's name in Azure
	Subscription  string        `json:"subscription,omitempty"` // default: the manager's
	ResourceGroup string        `json:"resourceGroup"`
	Location      string        `json:"location"`
	AddressSpace  string        `json:"addressSpace"`      // default 10.0.0.0/16
	Subnets       []AzureSubnet `json:"subnets"`           // default: app, the first /24
	SSHFrom       []string      `json:"sshFrom,omitempty"` // default: the manager's address
}

// AzureSubnet is a subnet Korta creates in an Azure network.
type AzureSubnet struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

const maxAzureSubnets = 20

// AzureNetwork returns a network role's Azure network, or nil for other roles.
func (r Role) AzureNetwork() *AzureNetwork {
	if len(r.Steps) > 0 && r.Steps[0].Type == "azure-network" {
		return r.Steps[0].AzureNetwork
	}
	return nil
}

func (n *AzureNetwork) normalize() error {
	if !roleNamePattern.MatchString(n.Name) {
		return fmt.Errorf("network name must be lowercase letters, digits and -, such as prod")
	}
	if n.Subscription != "" && !azureSubscription.MatchString(n.Subscription) {
		return fmt.Errorf("subscription must be a subscription UUID, or left out for the manager's default")
	}
	if !azureResource.MatchString(n.ResourceGroup) || strings.HasSuffix(n.ResourceGroup, ".") {
		return fmt.Errorf("resource-group must name an existing resource group, such as production")
	}
	if !azureLocation.MatchString(n.Location) {
		return fmt.Errorf("location must be a region such as eastus")
	}
	if n.AddressSpace == "" {
		n.AddressSpace = "10.0.0.0/16"
	}
	space, err := netip.ParsePrefix(n.AddressSpace)
	if err != nil || !space.Addr().Is4() || space.Bits() < 8 || space.Bits() > 29 {
		return fmt.Errorf("address-space must be an IPv4 range from /8 to /29, such as 10.10.0.0/16")
	}
	space = space.Masked()
	n.AddressSpace = space.String()
	if len(n.Subnets) == 0 {
		bits := max(space.Bits(), 24)
		n.Subnets = []AzureSubnet{{Name: "app", CIDR: netip.PrefixFrom(space.Addr(), bits).String()}}
	}
	if len(n.Subnets) > maxAzureSubnets {
		return fmt.Errorf("a network can have at most %d subnets", maxAzureSubnets)
	}
	seen := []netip.Prefix{}
	names := map[string]bool{}
	for i, s := range n.Subnets {
		if !azureResource.MatchString(s.Name) || strings.HasSuffix(s.Name, ".") || strings.EqualFold(s.Name, "GatewaySubnet") || strings.HasPrefix(strings.ToLower(s.Name), "azure") {
			return fmt.Errorf("subnet name %q must be letters, digits, _ . or -, and not reserved by Azure", s.Name)
		}
		if names[strings.ToLower(s.Name)] {
			return fmt.Errorf("subnet %s is listed twice", s.Name)
		}
		names[strings.ToLower(s.Name)] = true
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil || !p.Addr().Is4() || p.Bits() > 29 {
			return fmt.Errorf("subnet %s needs an IPv4 range of /29 or larger, such as 10.10.1.0/24", s.Name)
		}
		p = p.Masked()
		if !space.Contains(p.Addr()) || p.Bits() < space.Bits() {
			return fmt.Errorf("subnet %s (%s) is outside the network's %s", s.Name, p, space)
		}
		for _, o := range seen {
			if o.Overlaps(p) {
				return fmt.Errorf("subnets %s and %s overlap", o, p)
			}
		}
		seen = append(seen, p)
		n.Subnets[i].CIDR = p.String()
	}
	for i, c := range n.SSHFrom {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			if a, aerr := netip.ParseAddr(c); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return fmt.Errorf("ssh from %q must be an address or network such as 203.0.113.7 or 10.8.0.0/16", c)
			}
		}
		n.SSHFrom[i] = p.Masked().String()
	}
	return nil
}

// Subnet returns the named subnet, or the first one for an empty name.
func (n AzureNetwork) Subnet(name string) (AzureSubnet, bool) {
	for _, s := range n.Subnets {
		if name == "" || strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return AzureSubnet{}, false
}

// parseAzureNetwork reads an "# Azure network" section. A network role has
// no other sections.
func parseAzureNetwork(items []mdItem) (*Step, error) {
	var n *AzureNetwork
	seen := map[string]bool{}
	for _, it := range items {
		if it.kind != "azure-network" {
			if n != nil && it.kind != "vars" {
				return nil, it.errorf("a network role has only its Azure network section; configure VMs in their own roles with network: NAME")
			}
			continue
		}
		if n == nil {
			n = &AzureNetwork{}
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("Azure network settings use one flat bullet per field")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key = strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(key), "-", " ")), " ")
		value = strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("Azure network settings need unique field: value bullets")
		}
		if strings.ContainsAny(value, "{}$\n\r\x00") {
			return nil, it.errorf("Azure network settings must be literal values, without variables or secrets")
		}
		seen[key] = true
		switch key {
		case "name":
			n.Name = value
		case "subscription":
			n.Subscription = value
		case "resource group":
			n.ResourceGroup = value
		case "location", "region":
			n.Location = value
		case "address space", "cidr":
			n.AddressSpace = value
		case "subnets", "subnet":
			for _, entry := range strings.Split(value, ",") {
				parts := strings.Fields(strings.ReplaceAll(entry, "=", " "))
				if len(parts) != 2 {
					return nil, it.errorf("list subnets as NAME RANGE pairs, such as app 10.10.1.0/24, db 10.10.2.0/24")
				}
				n.Subnets = append(n.Subnets, AzureSubnet{Name: parts[0], CIDR: parts[1]})
			}
		case "ssh from":
			n.SSHFrom = strings.Fields(strings.ReplaceAll(value, ",", " "))
		default:
			return nil, it.errorf("unknown Azure network field; use name, subscription, resource-group, location, address-space, subnets or ssh from")
		}
	}
	if n == nil {
		return nil, nil
	}
	if err := n.normalize(); err != nil {
		return nil, fmt.Errorf("Azure network: %w", err)
	}
	return &Step{Type: "azure-network", Name: "Create Azure network " + n.Name, AzureNetwork: n}, nil
}

// ParseAzureNetwork reads the literal network section before variables are
// rendered.
func ParseAzureNetwork(src string) (*AzureNetwork, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	step, err := parseAzureNetwork(items)
	if err != nil || step == nil {
		return nil, err
	}
	return step.AzureNetwork, nil
}

func (n AzureNetwork) markdown() string {
	b := &strings.Builder{}
	field := func(k, v string) {
		if v != "" {
			fmt.Fprintf(b, "- %s: %s\n", k, v)
		}
	}
	subnets := []string{}
	for _, s := range n.Subnets {
		subnets = append(subnets, s.Name+" "+s.CIDR)
	}
	field("name", n.Name)
	field("subscription", n.Subscription)
	field("resource-group", n.ResourceGroup)
	field("location", n.Location)
	field("address-space", n.AddressSpace)
	field("subnets", strings.Join(subnets, ", "))
	field("ssh from", strings.Join(n.SSHFrom, ", "))
	return b.String()
}

// ProvisionsAzure reports whether a Markdown role creates Azure resources,
// which needs a Korta Enterprise manager.
func ProvisionsAzure(src string) (bool, error) {
	a, err := ParseAzure(src)
	if err != nil || a != nil {
		return a != nil, err
	}
	n, err := ParseAzureNetwork(src)
	return n != nil, err
}
