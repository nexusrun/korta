package roles

import (
	"strings"
	"testing"
)

func TestGCPRole(t *testing.T) {
	md := "# GCP instance\n- name: web\n- project: demo-project\n- zone: us-central1-a\n\n# Packages\n- nginx\n"
	role := Role{Name: "web", Markdown: md}
	if err := role.Normalize(); err != nil {
		t.Fatal(err)
	}
	if role.GCP() == nil || role.GCP().MachineType != "e2-micro" || len(role.Steps) != 2 {
		t.Fatalf("%+v", role)
	}
	round := Role{Name: "web", Markdown: ToMarkdown(role.Steps)}
	if err := round.Normalize(); err != nil || round.GCP() == nil {
		t.Fatalf("%s: %v", round.Markdown, err)
	}
	for _, bad := range []string{"# GCP instance\n- name: web\n- project: {{ secret.project }}\n- zone: us-central1-a", "# GCP instance\n- name: web\n- project: demo-project\n- zone: invalid", "# GCP instance\n- name: web\n- project: demo-project\n- zone: us-central1-a\n- size: e2-micro\n- machine-type: e2-small", "# GCP instance\n- name: web\n- project: demo-project\n- zone: us-central1-a\n\n# AWS instance\n- name: other"} {
		r := Role{Name: "test", Markdown: bad}
		if err := r.Normalize(); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if !strings.Contains(strings.Join(role.Risky(), " "), "billable") {
		t.Fatal(role.Risky())
	}
}
