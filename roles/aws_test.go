package roles

import (
	"reflect"
	"strings"
	"testing"
)

const awsMarkdown = `# AWS instance
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

func TestAWSMarkdown(t *testing.T) {
	r := Role{Name: "web", Markdown: awsMarkdown}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(r.Steps) != 2 || r.AWS() == nil || r.AWS().InstanceType != "t3.micro" || r.AWS().User != "ubuntu" || r.AWS().Address != "" {
		t.Fatalf("%+v", r)
	}
	md := ToMarkdown(r.Steps)
	round := Role{Name: "web", Markdown: md}
	if err := round.Normalize(); err != nil || round.AWS() == nil || len(round.Steps) != 2 {
		t.Fatalf("%s: %v", md, err)
	}
	for _, tc := range []struct{ name, md string }{
		{"unknown", strings.Replace(awsMarkdown, "name: web", "access-key: do-not-echo", 1)},
		{"duplicate", strings.Replace(awsMarkdown, "name: web", "name: web\n- name: other", 1)},
		{"secret", strings.Replace(awsMarkdown, "key-pair: deploy", "key-pair: {{ secret.AWS }}", 1)},
		{"variable", strings.Replace(awsMarkdown, "name: web", "name: {{ name }}", 1)},
		{"order", "# Packages\n- curl\n" + awsMarkdown},
		{"invalid-id", strings.Replace(awsMarkdown, "ami-12345678", "sg-12345678", 1)},
		{"nested", strings.Replace(awsMarkdown, "- name: web", "- name: web\n  - ignored: invalid", 1)},
		{"os-and-image", strings.Replace(awsMarkdown, "name: web", "name: web\n- os: ubuntu 24.04", 1)},
		{"half-key", strings.Replace(awsMarkdown, "- ssh-key: key_test\n", "", 1)},
		{"subnet-and-network", strings.Replace(awsMarkdown, "name: web", "name: web\n- network: prod", 1)},
		{"count", strings.Replace(awsMarkdown, "name: web", "name: web\n- count: 21", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Role{Name: "web", Markdown: tc.md}
			if err := r.Normalize(); err == nil {
				t.Fatal("accepted invalid AWS section")
			}
		})
	}
}

func TestAWSJSONSteps(t *testing.T) {
	r := Role{Name: "web", Markdown: awsMarkdown}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	r.Markdown = ""
	original := r.Hash()
	r.Steps[0].AWS.Image = "ami-87654321"
	if r.Hash() == original {
		t.Fatal("AWS changes did not change hash")
	}
	r.Steps[0], r.Steps[1] = r.Steps[1], r.Steps[0]
	if err := r.Normalize(); err == nil {
		t.Fatal("accepted AWS after configuration")
	}
}

// The shortest AWS section: Korta chooses the image, user, network, key
// and security group.
func TestAWSMinimalSection(t *testing.T) {
	r := Role{Name: "web", Markdown: "# AWS instance\n- name: web\n- count: 3\n- os: Rocky Linux 9\n- size: t3.small\n\n# Packages\n- nginx\n"}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	a := r.AWS()
	if a.OS != "rocky 9" || a.User != "rocky" || a.InstanceType != "t3.small" || a.Region != "" || a.Subnet != "" || a.KeyPair != "" || strings.Join(a.InstanceNames(), ",") != "web,web-2,web-3" {
		t.Fatalf("%+v", a)
	}
	if !strings.Contains(r.Steps[0].Name, "Create 3 AWS instances") || !strings.Contains(strings.Join(r.Risky(), ";"), "3 billable EC2 instances") {
		t.Fatal(r.Steps[0].Name, r.Risky())
	}
	md := ToMarkdown(r.Steps)
	round := Role{Name: "web", Markdown: md}
	if err := round.Normalize(); err != nil || !reflect.DeepEqual(round.AWS(), a) {
		t.Fatalf("%s: %v", md, err)
	}
	if strings.Contains(md, "image:") || strings.Contains(md, "subnet:") || !strings.Contains(md, "- count: 3") {
		t.Fatal(md)
	}
	plain := Role{Name: "web", Markdown: "# AWS instance\n- name: web\n"}
	if err := plain.Normalize(); err != nil || plain.AWS().OS != "ubuntu 24.04" || plain.AWS().User != "ubuntu" || plain.AWS().InstanceNames()[0] != "web" {
		t.Fatalf("%+v %v", plain.AWS(), err)
	}
}

func TestAWSRelease(t *testing.T) {
	for in, want := range map[string]string{
		"ubuntu 24.04": "ubuntu 24.04", "Ubuntu-22.04": "ubuntu 22.04", "Red Hat 9": "rhel 9", "alma linux 10": "almalinux 10",
		"CentOS Stream 10": "centos-stream 10", "debian 13": "debian 13",
	} {
		d, v, err := AWSRelease(in)
		if err != nil || d+" "+v != want {
			t.Errorf("%s: %s %s %v", in, d, v, err)
		}
	}
	for _, bad := range []string{"ubuntu", "ubuntu 20.04", "windows 2022", "amazon linux 2023", "centos stream 8"} {
		if _, _, err := AWSRelease(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
