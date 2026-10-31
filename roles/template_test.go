package roles

import (
	"strings"
	"testing"
)

const nginxRole = "# Variables\n" +
	"- domain = example.com\n" +
	"- app_port: `3000`\n\n" +
	"# Files\n" +
	"- /etc/nginx/conf.d/{{ domain }}.conf, mode 0644, check with nginx -t -c /etc/nginx/nginx.conf\n\n" +
	"```nginx\n" +
	"server {\n" +
	"    server_name {{domain}} www.{{ domain }};\n" +
	"    proxy_pass http://127.0.0.1:{{ app_port }};  # on {{ host.name }}\n" +
	"}\n" +
	"```\n\n" +
	"- /etc/keep.txt\n\n" +
	"```text raw\n" +
	"{{ .Values.keep }} {{ domain }}\n" +
	"```\n"

func TestVariablesAndRender(t *testing.T) {
	vars, err := Variables(nginxRole)
	if err != nil || vars["domain"] != "example.com" || vars["app_port"] != "3000" || len(vars) != 2 {
		t.Fatalf("%v %v", vars, err)
	}
	refs, err := References(nginxRole)
	if err != nil || strings.Join(refs, " ") != "domain app_port host.name" {
		t.Fatalf("%v %v", refs, err)
	}
	vars["domain"], vars["host.name"] = "shop.example.com", "web1"
	out, err := Render(nginxRole, vars)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/etc/nginx/conf.d/shop.example.com.conf", "server_name shop.example.com www.shop.example.com;", "127.0.0.1:3000;  # on web1", "{{ .Values.keep }} {{ domain }}"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") != strings.Count(nginxRole, "\n") {
		t.Fatal("rendering changed line numbers")
	}
	for _, tc := range []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"domain": "a", "app_port": "1"}, "line 11: {{ host.name }} is only known when the role runs on a host"},
		{map[string]string{"app_port": "1"}, "line 6: {{ domain }} is not set"},
		{map[string]string{"domain": "a\nb", "app_port": "1"}, "line 6: the value of domain spans lines; use it in a template file"},
	} {
		if _, err := Render(nginxRole, tc.vars); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want %q", err, tc.want)
		}
	}
	if _, err := Render("# Files\n- /etc/{{ domain | upper }}", nil); err == nil || !strings.Contains(err.Error(), "only plain variables") {
		t.Fatal(err)
	}
	for src, want := range map[string]string{
		"# Variables\n- 9lives = x":     "line 2: write variables as - name = value",
		"# Variables\n- a = 1\n- a = 2": "line 3: a is set twice",
		"# Variables\n- a = {{ b }}":    "line 2: a variable's value cannot use other variables",
	} {
		if _, err := Variables(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", src, err)
		}
	}
}

func TestCheckAndReloadSteps(t *testing.T) {
	src := "# Files\n- /etc/nginx/conf.d/a.conf, mode 0644, check with nginx -t -c /etc/nginx/nginx.conf\n\n```\nserver {}\n```\n" +
		"- /etc/sudoers.d/ops, mode 0440, check with `visudo -cf %s`\n\n```\nops ALL=(ALL) NOPASSWD: ALL\n```\n" +
		"# Services\n- nginx started, enabled, reload on change\n- postfix started, restart on change\n"
	r := Role{Name: "web", Markdown: src, Targets: Targets{InstanceIDs: []string{"x"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	s := r.Steps
	if s[0].Check != "nginx -t -c /etc/nginx/nginx.conf" || s[0].Path != "/etc/nginx/conf.d/a.conf" || s[1].Check != "visudo -cf %s" || !s[2].ReloadOnChange || s[2].RestartOnChange || !s[3].RestartOnChange {
		t.Fatalf("%+v", s)
	}
	if !r.HasCommand() || !strings.Contains(strings.Join(r.Risky(), ";"), "runs a check command as root: nginx -t") {
		t.Fatal("check commands must be reviewed like scripts")
	}
	back, err := ParseMarkdown(ToMarkdown(r.Steps))
	if err != nil || back[0].Check != s[0].Check || back[1].Check != s[1].Check || !back[2].ReloadOnChange {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	inPlace, _ := Script("web", s[0], Host{Family: "apt"}, true, false)
	before, _ := Script("web", s[1], Host{Family: "apt"}, true, false)
	reload, _ := Script("web", s[2], Host{Family: "apt"}, true, true)
	if !strings.Contains(inPlace, "the previous $path was put back") || !strings.Contains(before, `sed "s#%s#$tmp#g"`) || !strings.Contains(reload, `todo="$todo reload"`) {
		t.Fatal("scripts")
	}
	if plan, _ := Script("web", s[0], Host{Family: "apt"}, false, false); strings.Contains(plan, "sh -c") {
		t.Fatal("a plan ran the check")
	}
	if _, err := ParseMarkdown("# Directories\n- /opt/x, check with true"); err == nil || !strings.Contains(err.Error(), "only files can have a check command") {
		t.Fatal(err)
	}
}

func TestTemplateFiles(t *testing.T) {
	md := "# Variables\n- domain = example.com\n\n# Files\n" +
		"- /etc/nginx/conf.d/site.conf, mode 0644, from templates/site.conf, check with nginx -t\n" +
		"- /etc/helm/values.yaml from files/values.yaml, raw\n"
	r := Role{Name: "web", Markdown: md, Targets: Targets{InstanceIDs: []string{"x"}}, Files: map[string]string{
		"templates/site.conf": "server_name {{ domain }}; # {{ host.name }}\n",
		"files/values.yaml":   "image: {{ .Values.image }}\n",
	}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.Steps[0].Content != "server_name example.com; # example-host\n" || r.Steps[0].Check != "nginx -t" || r.Steps[1].Content != "image: {{ .Values.image }}\n" {
		t.Fatalf("%+v", r.Steps)
	}
	if err := r.Compile(map[string]string{"domain": "shop.example.com", "host.name": "web1"}); err != nil || r.Steps[0].Content != "server_name shop.example.com; # web1\n" {
		t.Fatalf("%v %q", err, r.Steps[0].Content)
	}
	if srcs, err := Sources(md); err != nil || strings.Join(srcs, " ") != "templates/site.conf files/values.yaml" {
		t.Fatalf("%v %v", srcs, err)
	}
	back, err := ParseMarkdown(ToMarkdown(r.Steps))
	if err != nil || back[0].Source != "templates/site.conf" || back[0].Check != "nginx -t" || !back[1].Raw {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	// A template's own mistakes name the file and its line.
	r.Files["templates/site.conf"] = "line one\nserver_name {{ missing }};\n"
	if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), "templates/site.conf: line 2: {{ missing }} is not set") {
		t.Fatal(err)
	}
	delete(r.Files, "templates/site.conf")
	if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), "template file templates/site.conf for /etc/nginx/conf.d/site.conf is missing") {
		t.Fatal(err)
	}
	for src, want := range map[string]string{
		"# Files\n- /etc/a from ../secrets\n":         "must be a path inside the role's folder",
		"# Files\n- /etc/a from /etc/passwd\n":        "must be a path inside the role's folder",
		"# Files\n- /etc/a from t/a\n\n```\nx\n```\n": "either a code block or from FILE, not both",
		"# Files\n- /etc/a, raw\n\n```\nx\n```\n":     "raw goes with from FILE",
		"# Files\n- /etc/a from t/{{ name }}.conf\n":  "template file names cannot use variables",
	} {
		_, err := Sources(src)
		if err == nil {
			_, err = ParseMarkdown(src)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", src, err)
		}
	}
}

func TestSecrets(t *testing.T) {
	md := "# Files\n- /etc/app/env, mode 0600\n\n```\nDB_PASSWORD={{ secret.db_password }}\n```\n- /etc/ssl/app.key, mode 0600, from tls/app.key\n"
	r := Role{Name: "app", Markdown: md, Files: map[string]string{"tls/app.key": "{{ secret.tls_key }}"}, Targets: Targets{InstanceIDs: []string{"x"}}}
	if refs := SecretRefs(r.Markdown, r.Files); strings.Join(refs, " ") != "db_password tls_key" {
		t.Fatal(refs)
	}
	// Saving checks the role with placeholders, never real values.
	if err := r.Normalize(); err != nil || r.Steps[0].Content != "DB_PASSWORD=SECRET\n" {
		t.Fatalf("%v %+v", err, r.Steps)
	}
	key := "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
	err := r.Compile(map[string]string{"secret.db_password": "hunter22", "secret.tls_key": key})
	if err != nil || r.Steps[0].Content != "DB_PASSWORD=hunter22\n" || r.Steps[1].Content != key {
		t.Fatalf("%v %+v", err, r.Steps)
	}
	// Multi-line values only go in template files.
	if err := r.Compile(map[string]string{"secret.db_password": key, "secret.tls_key": key}); err == nil || !strings.Contains(err.Error(), "spans lines; use it in a template file") {
		t.Fatal(err)
	}
	if err := r.Compile(map[string]string{"secret.tls_key": key}); err == nil || !strings.Contains(err.Error(), "korta secrets set db_password; offline, set KORTA_SECRET_DB_PASSWORD") {
		t.Fatal(err)
	}
	h := RedactResult(HostResult{Error: "failed: hunter22", Steps: []StepResult{{Detail: "echo hunter22 and abc"}}}, []string{"hunter22", "abc"})
	if h.Error != "failed: [secret]" || h.Steps[0].Detail != "echo [secret] and abc" {
		t.Fatalf("%+v", h)
	}
}
