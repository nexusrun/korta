package roles

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// AWSNetwork describes a VPC that Korta creates, or an existing one it
// adopts, with public and private subnets across availability zones.
// Instance roles place instances in it with "network: NAME". In an adopted
// VPC, Korta only adds resources of its own; it never changes or deletes
// anything it did not create.
type AWSNetwork struct {
	Name    string `json:"name"`
	Region  string `json:"region,omitempty"`  // default: the account's
	Account string `json:"account,omitempty"` // an AWS account entry on the manager
	VPC     string `json:"vpc,omitempty"`     // adopt this VPC instead of creating one
	CIDR    string `json:"cidr,omitempty"`    // a new VPC's range; default 10.0.0.0/16
	Zones   int    `json:"zones"`             // availability zones; default 2
	// Subnets are CIDRs Korta creates, one per zone, or in an adopted VPC
	// also the IDs of existing subnets. Empty lists are carved from the VPC
	// range; NoPublic or NoPrivate leaves that kind out.
	PublicSubnets  []string `json:"publicSubnets,omitempty"`
	PrivateSubnets []string `json:"privateSubnets,omitempty"`
	NoPublic       bool     `json:"noPublic,omitempty"`
	NoPrivate      bool     `json:"noPrivate,omitempty"`
	// NAT gives private subnets outbound internet access: one gateway,
	// one per zone, or none.
	NAT     string   `json:"nat,omitempty"`
	SSHFrom []string `json:"sshFrom,omitempty"` // who may SSH to instances; default the manager
}

var awsVPC = regexp.MustCompile(`^vpc-[0-9a-f]{8,17}$`)

const maxZones = 6

// AWSNetwork returns a network role's network, or nil for other roles.
func (r Role) AWSNetwork() *AWSNetwork {
	if len(r.Steps) > 0 && r.Steps[0].Type == "aws-network" {
		return r.Steps[0].Network
	}
	return nil
}

func (n *AWSNetwork) normalize() error {
	if !roleNamePattern.MatchString(n.Name) {
		return fmt.Errorf("network name must be lowercase letters, digits and -, such as prod")
	}
	if n.Region != "" && !awsRegion.MatchString(n.Region) {
		return fmt.Errorf("network region must be a region such as eu-west-1, or left out for the account's")
	}
	if n.Account != "" && !roleNamePattern.MatchString(n.Account) {
		return fmt.Errorf("network account must name an AWS account on the manager, such as prod")
	}
	var vpc netip.Prefix
	switch {
	case n.VPC != "" && n.CIDR != "":
		return fmt.Errorf("a network needs vpc (to adopt one) or cidr (to create one), not both")
	case n.VPC != "":
		if !awsVPC.MatchString(n.VPC) {
			return fmt.Errorf("vpc must be a VPC ID such as vpc-0123456789abcdef0")
		}
	default:
		if n.CIDR == "" {
			n.CIDR = "10.0.0.0/16"
		}
		p, err := netip.ParsePrefix(n.CIDR)
		if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 24 {
			return fmt.Errorf("cidr must be an IPv4 range from /16 to /24, such as 10.20.0.0/16")
		}
		vpc = p.Masked()
		n.CIDR = vpc.String()
	}
	if n.NoPublic && len(n.PublicSubnets) > 0 || n.NoPrivate && len(n.PrivateSubnets) > 0 {
		return fmt.Errorf("list subnets or say none, not both")
	}
	if n.NoPublic && n.NoPrivate {
		return fmt.Errorf("a network needs public or private subnets")
	}
	if n.Zones == 0 {
		n.Zones = max(len(n.PublicSubnets), len(n.PrivateSubnets), 2)
	}
	if n.Zones < 1 || n.Zones > maxZones {
		return fmt.Errorf("zones must be 1 to %d", maxZones)
	}
	seen := []netip.Prefix{}
	for _, list := range [][]string{n.PublicSubnets, n.PrivateSubnets} {
		if len(list) > 0 && len(list) != n.Zones {
			return fmt.Errorf("list one subnet per zone: %d zones, %d subnets", n.Zones, len(list))
		}
		for i, s := range list {
			if strings.HasPrefix(s, "subnet-") {
				if n.VPC == "" {
					return fmt.Errorf("existing subnets such as %s need vpc: the VPC they belong to", s)
				}
				if !awsID.MatchString(s) {
					return fmt.Errorf("%q is not a subnet ID", s)
				}
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 28 {
				return fmt.Errorf("subnet %q must be a subnet ID or an IPv4 range from /16 to /28", s)
			}
			p = p.Masked()
			if vpc.IsValid() && (!vpc.Contains(p.Addr()) || p.Bits() < vpc.Bits()) {
				return fmt.Errorf("subnet %s is outside the network's %s", p, vpc)
			}
			for _, o := range seen {
				if o.Overlaps(p) {
					return fmt.Errorf("subnets %s and %s overlap", o, p)
				}
			}
			seen = append(seen, p)
			list[i] = p.String()
		}
	}
	switch {
	case n.NAT == "" && (n.NoPrivate || n.NoPublic):
		n.NAT = "none"
	case n.NAT == "":
		n.NAT = "one"
	case n.NAT != "one" && n.NAT != "per-zone" && n.NAT != "none":
		return fmt.Errorf("nat must be one, per-zone or none")
	case n.NAT != "none" && (n.NoPrivate || n.NoPublic):
		return fmt.Errorf("a NAT gateway needs public and private subnets; set nat: none")
	}
	for i, c := range n.SSHFrom {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("ssh from %q must be a network such as 10.8.0.0/16", c)
		}
		n.SSHFrom[i] = p.Masked().String()
	}
	return nil
}

// NATGateways is how many NAT gateways the network runs.
func (n AWSNetwork) NATGateways() int {
	switch n.NAT {
	case "one":
		return 1
	case "per-zone":
		return n.Zones
	}
	return 0
}

// parseAWSNetwork reads a "# AWS network" section. A network role has no
// other sections.
func parseAWSNetwork(items []mdItem) (*Step, error) {
	var n *AWSNetwork
	seen := map[string]bool{}
	for _, it := range items {
		if it.kind != "aws-network" {
			if n != nil && it.kind != "vars" {
				return nil, it.errorf("a network role has only its AWS network section; configure instances in their own roles")
			}
			continue
		}
		if n == nil {
			n = &AWSNetwork{}
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("AWS network settings use one flat bullet per field")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("AWS network settings need unique field: value bullets")
		}
		if strings.ContainsAny(value, "{}$\n\r\x00") {
			return nil, it.errorf("AWS network settings must be literal values, without variables or secrets")
		}
		seen[key] = true
		list := strings.Fields(strings.ReplaceAll(value, ",", " "))
		switch key {
		case "name":
			n.Name = value
		case "region":
			n.Region = value
		case "account":
			n.Account = value
		case "vpc":
			n.VPC = value
		case "cidr":
			n.CIDR = value
		case "zones":
			z, err := strconv.Atoi(value)
			if err != nil {
				return nil, it.errorf("zones must be a number")
			}
			n.Zones = z
		case "public subnets":
			n.PublicSubnets, n.NoPublic = list, value == "none"
			if n.NoPublic {
				n.PublicSubnets = nil
			}
		case "private subnets":
			n.PrivateSubnets, n.NoPrivate = list, value == "none"
			if n.NoPrivate {
				n.PrivateSubnets = nil
			}
		case "nat":
			n.NAT = value
		case "ssh from":
			n.SSHFrom = list
		default:
			return nil, it.errorf("unknown AWS network field; use name, region, account, cidr or vpc, zones, public subnets, private subnets, nat or ssh from")
		}
	}
	if n == nil {
		return nil, nil
	}
	if err := n.normalize(); err != nil {
		return nil, fmt.Errorf("AWS network: %w", err)
	}
	name := "Create AWS network " + n.Name
	if n.VPC != "" {
		name = fmt.Sprintf("Use VPC %s as network %s", n.VPC, n.Name)
	}
	return &Step{Type: "aws-network", Name: name, Network: n}, nil
}

// ParseAWSNetwork reads the literal network section before variables are
// rendered.
func ParseAWSNetwork(src string) (*AWSNetwork, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	step, err := parseAWSNetwork(items)
	if err != nil || step == nil {
		return nil, err
	}
	return step.Network, nil
}

func (n AWSNetwork) markdown() string {
	b := &strings.Builder{}
	field := func(k, v string) {
		if v != "" {
			fmt.Fprintf(b, "- %s: %s\n", k, v)
		}
	}
	subnets := func(none bool, list []string) string {
		if none {
			return "none"
		}
		return strings.Join(list, ", ")
	}
	field("name", n.Name)
	field("region", n.Region)
	field("account", n.Account)
	field("vpc", n.VPC)
	field("cidr", n.CIDR)
	field("zones", strconv.Itoa(n.Zones))
	field("public subnets", subnets(n.NoPublic, n.PublicSubnets))
	field("private subnets", subnets(n.NoPrivate, n.PrivateSubnets))
	field("nat", n.NAT)
	field("ssh from", strings.Join(n.SSHFrom, ", "))
	return b.String()
}

// ProvisionsAWS reports whether a Markdown role creates AWS resources,
// which needs a Korta Enterprise manager.
func ProvisionsAWS(src string) (bool, error) {
	a, err := ParseAWS(src)
	if err != nil || a != nil {
		return a != nil, err
	}
	n, err := ParseAWSNetwork(src)
	return n != nil, err
}
