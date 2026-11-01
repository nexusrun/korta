package roles

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// GCPInstance describes Compute Engine instances and the existing subnet they use.
type GCPInstance struct {
	Name          string `json:"name"`
	Count         int    `json:"count,omitempty"`
	Project       string `json:"project"`
	Zone          string `json:"zone"`
	MachineType   string `json:"machineType"`
	ImageProject  string `json:"imageProject"`
	ImageFamily   string `json:"imageFamily"`
	SubnetProject string `json:"subnetProject"`
	Subnet        string `json:"subnet"`
	User          string `json:"user"`
	Address       string `json:"address"`
}

var gcpResourceName = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
var gcpZone = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`)

func (g *GCPInstance) normalize() error {
	if g.Count == 0 {
		g.Count = 1
	}
	if g.Count < 1 || g.Count > 20 || (g.Count > 1 && len(g.Name) > 60) {
		return fmt.Errorf("GCP count must be 1-20 and name at most 60 characters for multiple instances")
	}
	if g.MachineType == "" {
		g.MachineType = "e2-micro"
	}
	if g.ImageProject == "" {
		g.ImageProject = "ubuntu-os-cloud"
	}
	if g.ImageFamily == "" {
		g.ImageFamily = "ubuntu-2404-lts-amd64"
	}
	if g.SubnetProject == "" {
		g.SubnetProject = g.Project
	}
	if g.Subnet == "" {
		g.Subnet = "default"
	}
	if g.User == "" {
		g.User = "korta"
	}
	if g.Address == "" {
		g.Address = "public"
	}
	for _, v := range []string{g.Name, g.Project, g.Zone, g.MachineType, g.ImageProject, g.ImageFamily, g.SubnetProject, g.Subnet} {
		if !gcpResourceName.MatchString(v) {
			return fmt.Errorf("GCP settings need valid lowercase resource names; specify name, project and zone")
		}
	}
	if !gcpZone.MatchString(g.Zone) {
		return fmt.Errorf("GCP zone must be a zone such as us-central1-a")
	}
	if !accountPattern.MatchString(g.User) {
		return fmt.Errorf("GCP user must be a valid Linux login name")
	}
	if g.Address != "public" && g.Address != "private" {
		return fmt.Errorf("GCP address must be public or private")
	}
	return nil
}
func (g GCPInstance) InstanceNames() []string {
	out := []string{g.Name}
	for i := 2; i <= g.Count; i++ {
		out = append(out, fmt.Sprintf("%s-%d", g.Name, i))
	}
	return out
}
func (r Role) GCP() *GCPInstance {
	if len(r.Steps) > 0 && r.Steps[0].Type == "gcp-instance" {
		return r.Steps[0].GCP
	}
	return nil
}
func ParseGCP(src string) (*GCPInstance, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	step, err := parseGCP(items)
	if err != nil || step == nil {
		return nil, err
	}
	return step.GCP, nil
}
func parseGCP(items []mdItem) (*Step, error) {
	var g *GCPInstance
	seen := map[string]bool{}
	configured := false
	for _, it := range items {
		if it.kind != "gcp-instance" {
			if it.kind != "vars" {
				configured = true
			}
			continue
		}
		if configured {
			return nil, it.errorf("GCP instance must come before host configuration")
		}
		if g == nil {
			g = &GCPInstance{}
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("GCP settings use flat field: value bullets")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] || strings.ContainsAny(value, "{}$\n\r\x00") {
			return nil, it.errorf("GCP settings need unique literal field: value bullets")
		}
		seen[key] = true
		switch key {
		case "name":
			g.Name = value
		case "count":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, it.errorf("GCP count must be a number")
			}
			g.Count = n
		case "project":
			g.Project = value
		case "zone":
			g.Zone = value
		case "size", "machine-type":
			if seen["size"] && seen["machine-type"] {
				return nil, it.errorf("choose size or machine-type")
			}
			g.MachineType = value
		case "image-project":
			g.ImageProject = value
		case "image-family":
			g.ImageFamily = value
		case "subnet-project":
			g.SubnetProject = value
		case "subnet":
			g.Subnet = value
		case "user":
			g.User = value
		case "address":
			g.Address = value
		default:
			return nil, it.errorf("unknown GCP field; use name, count, project, zone, size, image-project, image-family, subnet-project, subnet, user or address")
		}
	}
	if g == nil {
		return nil, nil
	}
	if err := g.normalize(); err != nil {
		return nil, fmt.Errorf("GCP instance: %w", err)
	}
	return &Step{Type: "gcp-instance", Name: "Create GCP instance " + g.Name, GCP: g}, nil
}
