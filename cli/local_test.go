package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runLocal(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := Run(context.Background(), args, strings.NewReader(""), &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestInventoryCommand(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	inv := "# Databases\n- db1 ubuntu@10.0.0.5 env=prod\n\n# Web\n- web1 deploy@[fd00::7]:2222 env=staging\n"
	if err := os.WriteFile("inventory.md", []byte(inv), 0600); err != nil {
		t.Fatal(err)
	}
	// inventory.md in the current directory is the default.
	out, _, err := runLocal(t, "inventory")
	if err != nil || !strings.Contains(out, "db1   ubuntu@10.0.0.5") || !strings.Contains(out, "deploy@[fd00::7]:2222  Web") {
		t.Fatalf("%s %v", out, err)
	}
	out, _, err = runLocal(t, "inventory", "--limit", "env=staging", "--json")
	if err != nil || !strings.Contains(out, `"name": "web1"`) || strings.Contains(out, "db1") {
		t.Fatalf("%s %v", out, err)
	}
	if _, _, err = runLocal(t, "inventory", "--limit", "Databse"); err == nil || !strings.Contains(err.Error(), "groups: Databases, Web") {
		t.Fatal(err)
	}
	os.Remove("inventory.md")
	if _, _, err = runLocal(t, "plan", "role.md"); err == nil || !strings.Contains(err.Error(), "-i hosts.md") {
		t.Fatal(err)
	}
}

func TestLocalRoleAndConfirm(t *testing.T) {
	dir := t.TempDir()
	role := filepath.Join(dir, "Base Setup.md")
	os.WriteFile(role, []byte("# Packages\n- nginx\n"), 0600)
	c := &client{opts: options{values: map[string]string{}}}
	l, err := c.loadRole(role)
	if err != nil || l.name != "base-setup" {
		t.Fatalf("%+v %v", l, err)
	}
	r, err := l.compile(nil)
	if err != nil || len(r.Steps) != 1 || r.Rollout.BatchSize != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	os.WriteFile(role, []byte("# Users\n- test frobnicated\n"), 0600)
	if _, err = c.loadRole(role); err == nil || !strings.Contains(err.Error(), "Base Setup.md: line 2") {
		t.Fatal(err)
	}
	c.in = strings.NewReader("y\n") // not a terminal
	if err = c.confirm("Apply 2 changes to 1 host?"); err == nil || !strings.Contains(err.Error(), "add --yes") {
		t.Fatal(err)
	}
	c.opts.values["yes"] = "true"
	if err = c.confirm("Apply 2 changes to 1 host?"); err != nil {
		t.Fatal(err)
	}
}

func TestLocalPlanReportsUnreachableHosts(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "hosts.md")
	role := filepath.Join(dir, "role.md")
	os.WriteFile(inv, []byte("- db1 nobody@127.0.0.1:1\n"), 0600)
	os.WriteFile(role, []byte("# Packages\n- nginx\n"), 0600)
	out, _, err := runLocal(t, "plan", role, "-i", inv, "--ssh-config", os.DevNull, "--timeout", "30s")
	if err == nil || !strings.Contains(err.Error(), "the plan failed on 1 host") || !strings.Contains(out, "db1") || !strings.Contains(out, "failed") {
		t.Fatalf("%s %v", out, err)
	}
	_, _, err = runLocal(t, "apply", role, "-i", inv, "--ssh-config", os.DevNull, "--yes", "--timeout", "30s")
	if err == nil || !strings.Contains(err.Error(), "nothing was applied") {
		t.Fatal(err)
	}
}

func TestIdentityResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	inv := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	for _, f := range []string{filepath.Join(home, ".ssh", "prod"), filepath.Join(inv, "keys", "stg"), filepath.Join(home, "ci_key")} {
		os.MkdirAll(filepath.Dir(f), 0700)
		os.WriteFile(f, []byte("key"), 0600)
	}
	t.Setenv("CI_KEY", filepath.Join(home, "ci_key"))
	hostsFile := filepath.Join(inv, "hosts.md")
	os.WriteFile(hostsFile, []byte("# Production\nidentity: ~/.ssh/prod\n- db1 ubuntu@10.0.0.5\n- db2 ubuntu@10.0.0.6 identity=${CI_KEY}\n\n# Staging\nidentity: keys/stg\n- stg1 deploy@10.1.0.5\n"), 0600)

	out, _, err := runLocal(t, "inventory", "-i", hostsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"db1   ubuntu@10.0.0.5  Production  ~/.ssh/prod", "db2   ubuntu@10.0.0.6  Production  ~/ci_key", filepath.Join(inv, "keys", "stg")} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	// --identity replaces every host's key; its relative path is from here.
	t.Chdir(home)
	if out, _, err = runLocal(t, "inventory", "-i", hostsFile, "-k", "ci_key"); err != nil || strings.Count(out, " ci_key ") != 3 {
		t.Fatalf("%s %v", out, err)
	}
	t.Setenv("CI_KEY", "")
	if _, _, err = runLocal(t, "inventory", "-i", hostsFile); err == nil || !strings.Contains(err.Error(), "line 4: host db2: the identity uses $CI_KEY, which is not set") {
		t.Fatal(err)
	}
	if _, _, err = runLocal(t, "inventory", "-i", hostsFile, "--limit", "Staging", "--identity", "~/.ssh/missing"); err == nil || !strings.Contains(err.Error(), "missing: no such file") {
		t.Fatal(err)
	}
}

func TestIdentityReachesSSH(t *testing.T) {
	// A fake ssh records its arguments and fails like an unreachable host.
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> '"+argsFile+"'\nexit 255\n"), 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	key := filepath.Join(dir, "prod_key")
	os.WriteFile(key, []byte("key"), 0600)
	os.WriteFile(filepath.Join(dir, "hosts.md"), []byte("# Prod\nidentity: prod_key\n- db1 ubuntu@10.0.0.5:2222\n"), 0600)
	os.WriteFile(filepath.Join(dir, "role.md"), []byte("# Packages\n- nginx\n"), 0600)
	runLocal(t, "plan", filepath.Join(dir, "role.md"), "-i", filepath.Join(dir, "hosts.md"))
	b, _ := os.ReadFile(argsFile)
	args := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{"-i " + key + " -o IdentitiesOnly=yes", "-p 2222 -l ubuntu -- 10.0.0.5", "BatchMode=yes", "StrictHostKeyChecking=yes"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %s", want, args)
		}
	}
}

// fakeSSH answers OS detection like Ubuntu 24.04 and records every step
// script per host, reporting each step as a change.
func fakeSSH(t *testing.T) (logDir string) {
	t.Helper()
	bin, logDir := t.TempDir(), t.TempDir()
	script := `#!/bin/sh
host=""; while [ $# -gt 0 ]; do [ "$1" = "--" ] && { host=$2; break; }; shift; done
in=$(cat)
case "$in" in
  *KORTA_HOST*) echo "KORTA_HOST id=ubuntu version=24.04 codename=noble arch=x86_64 hostname=h cpus=2 mem_kb=4096000" ;;
  *) printf '%s\n' "$in" >> "` + logDir + `/$host"; echo "KORTA_RESULT changed would write" ;;
esac
`
	os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logDir
}

func TestVariablesPerHost(t *testing.T) {
	logs := fakeSSH(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hosts.md"), []byte("# Shop\nvars: domain=shop.example.com\n- web1 deploy@10.0.0.5\n- web2 deploy@10.0.0.6 app_port=4000\n\n# Blog\n- blog1 deploy@10.0.0.7 domain=blog.example.com secret=${BLOG_SECRET}\n\n# New\n- new1 deploy@10.0.0.8\n"), 0600)
	role := filepath.Join(dir, "site.md")
	os.WriteFile(role, []byte("# Variables\n- app_port = 3000\n\n# Files\n- /etc/nginx/conf.d/{{ domain }}.conf\n\n```nginx\nserver_name {{ domain }}; # {{ host.name }} {{ os.distro }}\nproxy_pass http://127.0.0.1:{{ app_port }};\n```\n"), 0600)
	t.Setenv("BLOG_SECRET", "s3cret")

	out, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md"))
	if err == nil || !strings.Contains(err.Error(), "the plan failed on 1 host") {
		t.Fatalf("%s %v", out, err)
	}
	// new1 has no domain: it fails with the line, the others still plan.
	if !strings.Contains(out, "new1") || !strings.Contains(out, "line 5: {{ domain }} is not set") || !strings.Contains(out, "/etc/nginx/conf.d/shop.example.com.conf") {
		t.Fatal(out)
	}
	content := func(host string) string {
		b, _ := os.ReadFile(filepath.Join(logs, host))
		return string(b)
	}
	for host, want := range map[string]string{
		"10.0.0.5": "server_name shop.example.com; # web1 ubuntu\nproxy_pass http://127.0.0.1:3000;\n",
		"10.0.0.6": "server_name shop.example.com; # web2 ubuntu\nproxy_pass http://127.0.0.1:4000;\n",
		"10.0.0.7": "server_name blog.example.com; # blog1 ubuntu\nproxy_pass http://127.0.0.1:3000;\n",
	} {
		if !strings.Contains(content(host), base64.StdEncoding.EncodeToString([]byte(want))) {
			t.Errorf("%s did not receive %q", host, want)
		}
	}
	// --var wins over the inventory and the role.
	os.RemoveAll(logs)
	os.MkdirAll(logs, 0700)
	if _, _, err = runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md"), "--limit", "web1", "--var", "domain=staging.example.com", "--var", "app_port=8080"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content("10.0.0.5"), base64.StdEncoding.EncodeToString([]byte("server_name staging.example.com; # web1 ubuntu\nproxy_pass http://127.0.0.1:8080;\n"))) {
		t.Fatal(content("10.0.0.5"))
	}
	// Secrets come from the environment, and a missing one fails clearly.
	t.Setenv("BLOG_SECRET", "")
	out, _, _ = runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md"), "--limit", "Blog")
	if !strings.Contains(out, "the variable secret uses ${BLOG_SECRET}, which is not set") {
		t.Fatal(out)
	}
}

func TestTemplateFilesOfflineAndUpload(t *testing.T) {
	logs := fakeSSH(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "templates"), 0700)
	os.WriteFile(filepath.Join(dir, "templates", "site.conf"), []byte("server_name {{ domain }};\n"), 0600)
	role := filepath.Join(dir, "site.md")
	os.WriteFile(role, []byte("# Files\n- /etc/nginx/conf.d/site.conf from templates/site.conf\n"), 0600)
	os.WriteFile(filepath.Join(dir, "hosts.md"), []byte("- web1 deploy@10.0.0.5 domain=shop.example.com\n"), 0600)
	if _, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(logs, "10.0.0.5"))
	if !strings.Contains(string(b), base64.StdEncoding.EncodeToString([]byte("server_name shop.example.com;\n"))) {
		t.Fatal("the template file was not rendered for the host")
	}
	// Uploading to a manager sends the template files with the role.
	o, _ := parse([]string{"roles", "create", "--file", role, "--name", "site", "--label", "env=prod"})
	c := client{opts: o}
	_, _, body, err := c.route()
	if err != nil || !strings.Contains(string(body), `"files":{"templates/site.conf":"server_name {{ domain }};\n"}`) {
		t.Fatalf("%s %v", body, err)
	}
	os.Remove(filepath.Join(dir, "templates", "site.conf"))
	if _, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md")); err == nil || !strings.Contains(err.Error(), "template file templates/site.conf") {
		t.Fatal(err)
	}
}

func TestSecretsCommands(t *testing.T) {
	route := func(stdin string, args ...string) (string, string, string, error) {
		o, err := parse(args)
		if err != nil {
			return "", "", "", err
		}
		c := client{opts: o, in: strings.NewReader(stdin)}
		m, p, b, err := c.route()
		return m, p, string(b), err
	}
	if m, p, b, err := route("hunter22\n", "secrets", "set", "db_password"); err != nil || m != "PUT" || p != "/api/secrets/db_password" || b != `{"value":"hunter22"}` {
		t.Fatalf("%s %s %s %v", m, p, b, err)
	}
	file := filepath.Join(t.TempDir(), "key")
	os.WriteFile(file, []byte("line1\nline2\n"), 0600)
	if _, _, b, err := route("", "secrets", "set", "tls_key", "--value-file", file); err != nil || b != `{"value":"line1\nline2"}` {
		t.Fatalf("%s %v", b, err)
	}
	for args, want := range map[string]string{
		"secrets set db_password --data {}": "not --data or --file",
		"secrets set DB":                    "secret names are lowercase",
		"secrets set empty":                 "is empty",
	} {
		if _, _, _, err := route("", strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", args, err)
		}
	}
	if m, p, _, err := route("", "secrets", "list"); err != nil || m != "GET" || p != "/api/secrets" {
		t.Fatal(m, p, err)
	}
}

func TestOfflineSecrets(t *testing.T) {
	logs := fakeSSH(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hosts.md"), []byte("- web1 deploy@10.0.0.5\n"), 0600)
	role := filepath.Join(dir, "app.md")
	os.WriteFile(role, []byte("# Files\n- /etc/app/env, mode 0600\n\n```\nDB_PASSWORD={{ secret.db_password }}\n```\n"), 0600)

	if out, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md")); !strings.Contains(out+fmt.Sprint(err), "offline, set KORTA_SECRET_DB_PASSWORD") {
		t.Fatal(out, err)
	}
	t.Setenv("KORTA_SECRET_DB_PASSWORD", "hunter22")
	if _, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(logs, "10.0.0.5"))
	if !strings.Contains(string(b), base64.StdEncoding.EncodeToString([]byte("DB_PASSWORD=hunter22\n"))) {
		t.Fatal("the secret did not reach the host")
	}
	// Secrets cannot come from the inventory or --var.
	if out, _, err := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md"), "--var", "secret.db_password=x"); !strings.Contains(out+fmt.Sprint(err), "secret.db_password is a secret: set KORTA_SECRET_DB_PASSWORD") {
		t.Fatal(out, err)
	}
	// A step that prints the secret has it blanked out.
	os.WriteFile(role, []byte("# Commands\n- `echo {{ secret.db_password }}; exit 3`\n"), 0600)
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nin=$(cat)\ncase \"$in\" in *KORTA_HOST*) echo 'KORTA_HOST id=ubuntu version=24.04 codename=noble arch=x86_64 hostname=h cpus=2 mem_kb=4096000' ;; *) echo 'leaked hunter22'; exit 1 ;; esac\n"), 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, _, _ := runLocal(t, "plan", role, "-i", filepath.Join(dir, "hosts.md"), "--json")
	if strings.Contains(out, "hunter22") || !strings.Contains(out, "leaked [secret]") {
		t.Fatal(out)
	}
}
