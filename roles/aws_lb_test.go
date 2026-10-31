package roles

import (
	"reflect"
	"strings"
	"testing"
)

const cert = "arn:aws:acm:us-east-1:123456789012:certificate/0123abcd-0123-4567-89ab-0123456789ab"

func TestAWSLoadBalancer(t *testing.T) {
	r := Role{Name: "web", Markdown: "# AWS instance\n- name: web\n- count: 2\n\n# AWS load balancer\n- certificate: " + cert + "\n- forward: 8080\n- health check: /health\n\n# Packages\n- nginx\n"}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	lb := r.AWS().LoadBalancer
	if lb == nil || lb.Listen != "https" || lb.Forward != 8080 || lb.HealthCheck != "/health" || lb.From[0] != "0.0.0.0/0" || len(lb.Ports()) != 2 || len(r.Steps) != 2 {
		t.Fatalf("%+v %d", lb, len(r.Steps))
	}
	if !strings.Contains(strings.Join(r.Risky(), ";"), "load balancer") {
		t.Fatal(r.Risky())
	}
	md := ToMarkdown(r.Steps)
	round := Role{Name: "web", Markdown: md}
	if err := round.Normalize(); err != nil || !reflect.DeepEqual(round.AWS(), r.AWS()) {
		t.Fatalf("%s %v", md, err)
	}
	plain := Role{Name: "web", Markdown: "# AWS instance\n- name: web\n\n# AWS LB\n- internal: yes\n"}
	if err := plain.Normalize(); err != nil || plain.AWS().LoadBalancer.Listen != "http" || !plain.AWS().LoadBalancer.Internal {
		t.Fatal(err)
	}
	for name, md := range map[string]string{
		"https-no-cert": "# AWS instance\n- name: web\n\n# AWS load balancer\n- listen: https\n",
		"bad-cert":      "# AWS instance\n- name: web\n\n# AWS load balancer\n- certificate: arn:aws:iam::1:role/x\n",
		"no-instance":   "# AWS load balancer\n- listen: http\n\n# Packages\n- nginx\n",
		"after-config":  "# AWS instance\n- name: web\n\n# Packages\n- nginx\n\n# AWS load balancer\n- listen: http\n",
		"two":           "# AWS instance\n- name: web\n\n# AWS load balancer\n- listen: http\n\n# AWS load balancer\n- forward: 81\n",
		"health":        "# AWS instance\n- name: web\n\n# AWS load balancer\n- health check: health\n",
		"from":          "# AWS instance\n- name: web\n\n# AWS load balancer\n- from: everyone\n",
	} {
		r := Role{Name: "web", Markdown: md}
		if err := r.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
