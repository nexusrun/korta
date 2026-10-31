package roles

import (
	"reflect"
	"testing"
)

func TestAWSDNS(t *testing.T) {
	md := "# AWS instance\n- name: web\n\n# AWS load balancer\n- certificate: auto\n\n# AWS DNS\n- Web.Example.com.\n- *.app.example.com\n\n# Packages\n- nginx\n"
	r := Role{Name: "web", Markdown: md}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	a := r.AWS()
	if !reflect.DeepEqual(a.DNS, []string{"web.example.com", "*.app.example.com"}) || a.LoadBalancer.Listen != "https" || a.LoadBalancer.Certificate != "auto" {
		t.Fatalf("%+v %+v", a.DNS, a.LoadBalancer)
	}
	round := Role{Name: "web", Markdown: ToMarkdown(r.Steps)}
	if err := round.Normalize(); err != nil || !reflect.DeepEqual(round.AWS(), a) {
		t.Fatalf("%s %v", ToMarkdown(r.Steps), err)
	}
	for name, md := range map[string]string{
		"auto-without-names": "# AWS instance\n- name: web\n\n# AWS load balancer\n- certificate: auto\n",
		"not-a-name":         "# AWS instance\n- name: web\n\n# AWS DNS\n- localhost\n",
		"field":              "# AWS instance\n- name: web\n\n# AWS DNS\n- name: web.example.com\n",
		"twice":              "# AWS instance\n- name: web\n\n# AWS DNS\n- a.example.com\n- A.example.com\n",
		"variable":           "# AWS instance\n- name: web\n\n# AWS DNS\n- {{ host }}.example.com\n",
		"no-instance":        "# AWS DNS\n- web.example.com\n\n# Packages\n- nginx\n",
		"after-config":       "# AWS instance\n- name: web\n\n# Packages\n- nginx\n\n# AWS DNS\n- web.example.com\n",
	} {
		if err := (&Role{Name: "web", Markdown: md}).Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
