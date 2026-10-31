package inventory

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	src := "Production hosts.\n\n" +
		"# Databases\n" +
		"- db1 ubuntu@10.0.0.5 env=prod\n" +
		"- db2 ubuntu@10.0.0.6:2222 env=prod\n" +
		"  - role=replica\n" +
		"## Analytics\n" +
		"- `warehouse` root@[fd00::5]:22\n\n" +
		"# Web\n" +
		"- web1 deploy@web1.internal env=staging\n" +
		"- web2.internal\n" +
		"- 10.0.0.9 team=web\n" +
		"```\n- not-a-host x@y\n```\n"
	hosts, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, h := range hosts {
		got = append(got, strings.Join([]string{h.Name, h.User, h.Address, strconv.Itoa(h.Port), strings.Join(h.Groups, "/"), labels(h)}, "|"))
	}
	want := []string{
		"db1|ubuntu|10.0.0.5|0|Databases|env=prod",
		"db2|ubuntu|10.0.0.6|2222|Databases|env=prod,role=replica",
		"warehouse|root|fd00::5|22|Databases/Analytics|",
		"web1|deploy|web1.internal|0|Web|env=staging",
		"web2.internal||web2.internal|0|Web|",
		"10.0.0.9||10.0.0.9|0|Web|team=web",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s", strings.Join(got, "\n"))
	}

	for limit, names := range map[string]string{
		"":                   "db1 db2 warehouse web1 web2.internal 10.0.0.9",
		"databases":          "db1 db2 warehouse",
		"Analytics":          "warehouse",
		"env=prod":           "db1 db2",
		"web1, role=replica": "db2 web1",
		"Web,team=web,web1":  "web1 web2.internal 10.0.0.9",
	} {
		sel, err := Select(hosts, limit)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, h := range sel {
			out = append(out, h.Name)
		}
		if strings.Join(out, " ") != names {
			t.Errorf("--limit %q: %v", limit, out)
		}
	}
	if _, err := Select(hosts, "Databse"); err == nil || !strings.Contains(err.Error(), "groups: Analytics, Databases, Web") {
		t.Fatal(err)
	}
}

func TestParseErrors(t *testing.T) {
	for src, want := range map[string]string{
		"# Hosts\n- db1 ubuntu@10.0.0.5 prod": `line 2: cannot tell what "prod" means`,
		"- db1 10.0.0.5\n- DB1 10.0.0.6":      "line 2: DB1 is already listed on line 1",
		"- db1 ubuntu@10.0.0.5:99999":         `line 1: port "99999" must be 1-65535`,
		"- db1 fd00::5":                       "line 1: write IPv6 addresses in brackets",
		"- db1 bad$user@10.0.0.5":             `line 1: invalid SSH user "bad$user"`,
		"- env=prod":                          "line 1: start the bullet with the host",
		"Only notes here.":                    "the inventory lists no hosts",
		"- db1 ubuntu@10.0.0.5 e$v=a":         `line 1: the name in "e$v=a"`,
		"- db1 ubuntu@10.0.0.5 env=":          "line 1: env needs a value",
	} {
		if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
}

func labels(h Host) string {
	out := []string{}
	for _, k := range []string{"env", "role", "team"} {
		if v, ok := h.Labels[k]; ok {
			out = append(out, k+"="+v)
		}
	}
	return strings.Join(out, ",")
}

func TestGroupSettings(t *testing.T) {
	src := "identity: ~/.ssh/default\n\n" +
		"# Production\n" +
		"identity: ~/.ssh/prod_ed25519\n" +
		"User: ubuntu\n" +
		"- db1 10.0.0.5\n" +
		"- db2 admin@10.0.0.6 identity=${DB2_KEY}\n" +
		"## Edge\n" +
		"- edge1 10.0.9.1\n" +
		"# Staging\n" +
		"- stg1 deploy@10.1.0.5\n"
	hosts, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, h := range hosts {
		got = append(got, h.Name+"|"+h.User+"|"+h.Identity)
	}
	want := []string{
		"db1|ubuntu|~/.ssh/prod_ed25519",
		"db2|admin|${DB2_KEY}",
		"edge1|ubuntu|~/.ssh/prod_ed25519", // subgroups inherit
		"stg1|deploy|~/.ssh/default",       // a new group starts from the file-wide setting
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
	if _, ok := hosts[1].Labels["identity"]; ok {
		t.Fatal("identity= became a label")
	}
	for src, want := range map[string]string{
		"# P\nuser: bad user\n- db1 10.0.0.5":     `line 2: invalid SSH user "bad user"`,
		"# P\nidentity: ~/my key\n- db1 10.0.0.5": "line 2: identity must be a private key file path",
		"- db1 10.0.0.5 identity=~/k;rm":          "line 1: identity must be a private key file path",
	} {
		if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", src, err)
		}
	}
}

func TestVariables(t *testing.T) {
	src := "vars: org=acme\n" +
		"# Shop\n" +
		"vars: domain=shop.example.com app_port=3000 title=\"Acme Shop, online\"\n" +
		"- web1 deploy@10.0.0.5\n" +
		"- web2 deploy@10.0.0.6 app_port=4000 url=https://shop.example.com/health?x=1\n" +
		"## Canary\n" +
		"vars: app_port=5000\n" +
		"- web3 deploy@10.0.0.7\n" +
		"# Blog\n" +
		"- blog1 deploy@10.0.1.5 db_password=${BLOG_DB_PASSWORD}\n"
	hosts, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"org": "acme", "domain": "shop.example.com", "app_port": "3000", "title": "Acme Shop, online"},
		{"org": "acme", "domain": "shop.example.com", "app_port": "4000", "title": "Acme Shop, online", "url": "https://shop.example.com/health?x=1"},
		{"org": "acme", "domain": "shop.example.com", "app_port": "5000", "title": "Acme Shop, online"},
		{"org": "acme", "db_password": "${BLOG_DB_PASSWORD}"},
	}
	for i, h := range hosts {
		if !reflect.DeepEqual(h.Labels, want[i]) {
			t.Errorf("%s: %v", h.Name, h.Labels)
		}
	}
	// Variables are labels, so --limit can select by them.
	if sel, _ := Select(hosts, "domain=shop.example.com"); len(sel) != 3 {
		t.Fatal(sel)
	}
}
