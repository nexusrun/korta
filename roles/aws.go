package roles

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AWSInstance describes the EC2 instances a role creates. Only Name is
// required: the manager picks the official image for OS, the login user,
// the network, a security group and an SSH key. The other fields override
// those choices for accounts that manage their own resources. Credentials
// belong to the manager's AWS credential chain, never to a role.
type AWSInstance struct {
	Name           string   `json:"name"`
	Count          int      `json:"count,omitempty"`   // instances name, name-2 ... name-N
	OS             string   `json:"os,omitempty"`      // such as "ubuntu 24.04"
	Network        string   `json:"network,omitempty"` // a network an admin defined on the manager
	Region         string   `json:"region"`
	Image          string   `json:"image"`
	InstanceType   string   `json:"instanceType"`
	Subnet         string   `json:"subnet"`
	SecurityGroups []string `json:"securityGroups"`
	KeyPair        string   `json:"keyPair"`
	SSHKey         string   `json:"sshKey"` // vault key ID matching KeyPair
	User           string   `json:"user"`
	Address        string   `json:"address"` // public or private; empty uses the network's, or public
}

var awsID = regexp.MustCompile(`^(ami|subnet|sg)-[0-9a-f]{8,17}$`)
var awsRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
var awsType = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z0-9]+$`)
var awsKeyPair = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ /@+-]{0,254}$`)
var vaultKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
var awsVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

const (
	maxAWSCount = 20
	defaultOS   = "ubuntu 24.04"
)

// awsSystems are the operating systems Korta launches from their
// publishers' official images, with each image's login user.
var awsSystems = map[string]struct {
	versions []string
	user     string
}{
	"ubuntu":        {[]string{"22.04", "24.04"}, "ubuntu"},
	"debian":        {[]string{"12", "13"}, "admin"},
	"rhel":          {[]string{"8", "9", "10"}, "ec2-user"},
	"rocky":         {[]string{"8", "9", "10"}, "rocky"},
	"almalinux":     {[]string{"8", "9", "10"}, "ec2-user"},
	"centos-stream": {[]string{"9", "10"}, "ec2-user"},
}

var awsAliases = map[string]string{
	"red hat": "rhel", "redhat": "rhel", "red hat enterprise linux": "rhel",
	"rocky linux": "rocky", "alma": "almalinux", "alma linux": "almalinux",
	"centos": "centos-stream", "centos stream": "centos-stream",
}

// AWSRelease splits an os value such as "Rocky Linux 9" into its canonical
// distribution and version, "rocky" and "9".
func AWSRelease(os string) (distro, version string, err error) {
	words := strings.Fields(strings.ToLower(strings.NewReplacer("-", " ", "_", " ").Replace(os)))
	if len(words) < 2 || !awsVersion.MatchString(words[len(words)-1]) {
		return "", "", fmt.Errorf("AWS os needs a name and version, such as ubuntu 24.04")
	}
	distro, version = strings.Join(words[:len(words)-1], " "), words[len(words)-1]
	if alias, ok := awsAliases[distro]; ok {
		distro = alias
	}
	sys, ok := awsSystems[strings.ReplaceAll(distro, " ", "-")]
	if !ok {
		return "", "", fmt.Errorf("AWS os %q is not supported; use ubuntu, debian, rhel, rocky, almalinux or centos-stream with a version", os)
	}
	distro = strings.ReplaceAll(distro, " ", "-")
	for _, v := range sys.versions {
		if v == version {
			return distro, version, nil
		}
	}
	return "", "", fmt.Errorf("AWS os %s supports versions %s", distro, strings.Join(sys.versions, ", "))
}

// InstanceNames lists the instances the step creates, in order: name, then
// name-2 to name-N, so raising count from 1 keeps the first instance.
func (a AWSInstance) InstanceNames() []string {
	out := []string{a.Name}
	for i := 2; i <= a.Count; i++ {
		out = append(out, fmt.Sprintf("%s-%d", a.Name, i))
	}
	return out
}

func (a *AWSInstance) normalize() error {
	if a.InstanceType == "" {
		a.InstanceType = "t3.micro"
	}
	if a.Count == 0 {
		a.Count = 1
	}
	if !roleNamePattern.MatchString(a.Name) || a.Count > 1 && len(a.Name) > 60 {
		return fmt.Errorf("AWS name must be lowercase letters, digits and -, at most 60 characters with a count")
	}
	if a.Count < 1 || a.Count > maxAWSCount {
		return fmt.Errorf("AWS count must be 1 to %d", maxAWSCount)
	}
	if a.Region != "" && !awsRegion.MatchString(a.Region) {
		return fmt.Errorf("AWS region must be a region such as us-east-1, or left out for the manager's region")
	}
	switch {
	case a.Image != "" && a.OS != "":
		return fmt.Errorf("AWS needs os or image, not both: os picks the official image")
	case a.Image != "":
		if !strings.HasPrefix(a.Image, "ami-") || !awsID.MatchString(a.Image) {
			return fmt.Errorf("AWS image must be an AMI ID, or use os such as ubuntu 24.04")
		}
		if a.User == "" {
			a.User = "ubuntu"
		}
	default:
		if a.OS == "" {
			a.OS = defaultOS
		}
		distro, version, err := AWSRelease(a.OS)
		if err != nil {
			return err
		}
		a.OS = distro + " " + version
		if a.User == "" {
			a.User = awsSystems[distro].user
		}
	}
	if !awsType.MatchString(a.InstanceType) {
		return fmt.Errorf("AWS instance-type must be a type such as t3.micro")
	}
	if a.Subnet != "" && a.Network != "" {
		return fmt.Errorf("AWS needs subnet or network, not both")
	}
	if a.Subnet != "" && (!strings.HasPrefix(a.Subnet, "subnet-") || !awsID.MatchString(a.Subnet)) {
		return fmt.Errorf("AWS subnet must be a subnet ID, or left out")
	}
	if a.Network != "" && !roleNamePattern.MatchString(a.Network) {
		return fmt.Errorf("AWS network must name a network defined on the manager, such as prod")
	}
	if len(a.SecurityGroups) > 5 {
		return fmt.Errorf("AWS security-groups takes at most 5 groups")
	}
	seen := map[string]bool{}
	for _, id := range a.SecurityGroups {
		if !strings.HasPrefix(id, "sg-") || !awsID.MatchString(id) || seen[id] {
			return fmt.Errorf("AWS security-groups must contain distinct security group IDs")
		}
		seen[id] = true
	}
	if (a.KeyPair == "") != (a.SSHKey == "") {
		return fmt.Errorf("AWS key-pair and ssh-key go together; leave both out and Korta creates a key")
	}
	if a.KeyPair != "" && (!awsKeyPair.MatchString(a.KeyPair) || !vaultKeyID.MatchString(a.SSHKey)) {
		return fmt.Errorf("AWS key-pair must be an EC2 key pair name and ssh-key a vault key ID")
	}
	if !accountPattern.MatchString(a.User) {
		return fmt.Errorf("AWS user must be the image's SSH login user")
	}
	// Left out, the network's address applies, or public.
	if a.Address != "" && a.Address != "public" && a.Address != "private" {
		return fmt.Errorf("AWS address must be public or private")
	}
	return nil
}

// AWS returns the first step's provisioning request, or nil for host-only roles.
func (r Role) AWS() *AWSInstance {
	if len(r.Steps) > 0 && r.Steps[0].Type == "aws-instance" {
		return r.Steps[0].AWS
	}
	return nil
}

// ParseAWS reads the literal provisioning section before variables are rendered.
// Cloud settings cannot depend on secrets or on facts from a host not yet created.
func ParseAWS(src string) (*AWSInstance, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	step, err := parseAWS(items)
	if err != nil || step == nil {
		return nil, err
	}
	return step.AWS, nil
}

func parseAWS(items []mdItem) (*Step, error) {
	var a *AWSInstance
	seen := map[string]bool{}
	configured := false
	for _, it := range items {
		if it.kind != "aws-instance" {
			if it.kind != "vars" {
				configured = true
			}
			continue
		}
		if configured {
			return nil, it.errorf("AWS instance must come before host configuration")
		}
		if a == nil {
			a = &AWSInstance{}
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("AWS settings use one flat bullet per field")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("AWS settings need unique field: value bullets")
		}
		if strings.ContainsAny(value, "{}$\n\r\x00") {
			return nil, it.errorf("AWS settings must be literal values, without variables or secrets")
		}
		seen[key] = true
		switch key {
		case "name":
			a.Name = value
		case "count":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, it.errorf("AWS count must be a number")
			}
			a.Count = n
		case "os":
			a.OS = value
		case "network":
			a.Network = value
		case "region":
			a.Region = value
		case "image":
			a.Image = value
		case "instance-type", "size":
			a.InstanceType = value
		case "subnet":
			a.Subnet = value
		case "security-groups":
			a.SecurityGroups = strings.Fields(strings.ReplaceAll(value, ",", " "))
		case "key-pair":
			a.KeyPair = value
		case "ssh-key":
			a.SSHKey = value
		case "user":
			a.User = value
		case "address":
			a.Address = value
		default:
			return nil, it.errorf("unknown AWS field; use name, count, os, size, network, region, address, or to override Korta's choices image, subnet, security-groups, key-pair, ssh-key and user")
		}
	}
	if a == nil {
		return nil, nil
	}
	if err := a.normalize(); err != nil {
		return nil, fmt.Errorf("AWS instance: %w", err)
	}
	name := "Create AWS instance " + a.Name
	if a.Count > 1 {
		name = fmt.Sprintf("Create %d AWS instances %s", a.Count, strings.Join(a.InstanceNames(), ", "))
	}
	return &Step{Type: "aws-instance", Name: name, AWS: a}, nil
}
