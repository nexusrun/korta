package roles

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AzureInstance describes Linux virtual machines in an existing Azure subnet.
type AzureInstance struct {
	// Network names a network built by an Azure network role. It supplies
	// the subscription, resource group, location and virtual network, and
	// Korta creates each VM's network interface and public IP.
	Network          string `json:"network,omitempty"`
	NetworkInterface string `json:"networkInterface"`
	Image            string `json:"image"`
	Name             string `json:"name"`
	Count            int    `json:"count,omitempty"`
	Subscription     string `json:"subscription"`
	ResourceGroup    string `json:"resourceGroup"`
	Location         string `json:"location"`
	Size             string `json:"size"`
	VirtualNetwork   string `json:"virtualNetwork"`
	Subnet           string `json:"subnet"`
	User             string `json:"user"`
	Address          string `json:"address"`
}

var azureSubscription = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var azureResource = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.()-]{0,79}$`)
var azureVMName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,59}$`)
var azureLocation = regexp.MustCompile(`^[a-z0-9]{2,40}$`)

func (a *AzureInstance) normalize() error {
	if a.Count == 0 {
		a.Count = 1
	}
	if a.Count < 1 || a.Count > 20 {
		return fmt.Errorf("Azure count must be 1-20")
	}
	if a.Size == "" {
		a.Size = "Standard_B2s"
	}
	if a.User == "" {
		a.User = "korta"
	}
	if a.Address == "" {
		a.Address = "public"
	}
	if !azureVMName.MatchString(a.Name) || strings.HasSuffix(a.Name, "-") {
		return fmt.Errorf("Azure name must start with a lowercase letter, contain lowercase letters, numbers or hyphens, and be at most 60 characters")
	}
	if a.Network != "" {
		if !roleNamePattern.MatchString(a.Network) {
			return fmt.Errorf("Azure network must name an Azure network role's network, such as prod")
		}
		if a.Subscription != "" || a.ResourceGroup != "" || a.Location != "" || a.VirtualNetwork != "" || a.NetworkInterface != "" {
			return fmt.Errorf("network %s supplies the subscription, resource-group, location and virtual-network, and Korta creates the network interface; remove those fields", a.Network)
		}
		for _, v := range []string{a.Size, a.Subnet} {
			if v != "" && (!azureResource.MatchString(v) || strings.HasSuffix(v, ".")) {
				return fmt.Errorf("Azure size and subnet must be valid resource names")
			}
		}
	} else {
		if !azureSubscription.MatchString(a.Subscription) {
			return fmt.Errorf("Azure subscription must be a subscription UUID")
		}
		for _, v := range []string{a.ResourceGroup, a.VirtualNetwork, a.Subnet, a.Size} {
			if !azureResource.MatchString(v) || strings.HasSuffix(v, ".") {
				return fmt.Errorf("Azure resource group, size, virtual network and subnet must be valid resource names; or use network: NAME for a network Korta builds")
			}
		}
		if !azureLocation.MatchString(a.Location) {
			return fmt.Errorf("Azure location must be a region such as eastus")
		}
	}
	if !accountPattern.MatchString(a.User) {
		return fmt.Errorf("Azure user must be a valid Linux login name")
	}
	if a.Address != "public" && a.Address != "private" {
		return fmt.Errorf("Azure address must be public or private")
	}
	return nil
}
func (a AzureInstance) InstanceNames() []string {
	out := []string{a.Name}
	for i := 2; i <= a.Count; i++ {
		out = append(out, fmt.Sprintf("%s-%d", a.Name, i))
	}
	return out
}
func (r Role) Azure() *AzureInstance {
	if len(r.Steps) > 0 && r.Steps[0].Type == "azure-instance" {
		return r.Steps[0].Azure
	}
	return nil
}
func ParseAzure(src string) (*AzureInstance, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	step, err := parseAzure(items)
	if err != nil || step == nil {
		return nil, err
	}
	return step.Azure, nil
}
func parseAzure(items []mdItem) (*Step, error) {
	var a *AzureInstance
	seen := map[string]bool{}
	configured := false
	for _, it := range items {
		if it.kind != "azure-instance" {
			if it.kind != "vars" {
				configured = true
			}
			continue
		}
		if configured {
			return nil, it.errorf("Azure instance must come before host configuration")
		}
		if a == nil {
			a = &AzureInstance{}
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("Azure settings use flat field: value bullets")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] || strings.ContainsAny(value, "{}$\n\r\x00") {
			return nil, it.errorf("Azure settings need unique literal field: value bullets")
		}
		seen[key] = true
		switch key {
		case "network":
			a.Network = value
		case "network-interface":
			a.NetworkInterface = value
		case "image":
			a.Image = value
		case "name":
			a.Name = value
		case "count":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, it.errorf("Azure count must be a number")
			}
			a.Count = n
		case "subscription":
			a.Subscription = value
		case "resource-group":
			a.ResourceGroup = value
		case "location":
			a.Location = value
		case "size":
			a.Size = value
		case "virtual-network":
			a.VirtualNetwork = value
		case "subnet":
			a.Subnet = value
		case "user":
			a.User = value
		case "address":
			a.Address = value
		default:
			return nil, it.errorf("unknown Azure field; use name, count, network, subscription, resource-group, location, size, virtual-network, subnet, user or address")
		}
	}
	if a == nil {
		return nil, nil
	}
	if err := a.normalize(); err != nil {
		return nil, fmt.Errorf("Azure instance: %w", err)
	}
	return &Step{Type: "azure-instance", Name: "Create Azure instance " + a.Name, Azure: a}, nil
}
