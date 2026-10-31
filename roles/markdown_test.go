package roles

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseMarkdownExample(t *testing.T) {
	src := `#Create users
 - test added to database group
 - app user added to apps group

#create directories
 - /opt/db
 - /opt/app
`
	steps, err := ParseMarkdown(src)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, s := range steps {
		name := s.User + s.Path
		if s.Type == "group" {
			name = s.Group
		}
		got = append(got, s.Type+" "+name+" "+strings.Join(s.Groups, ","))
	}
	want := []string{"group database ", "user test database", "group apps ", "user app apps", "directory /opt/db ", "directory /opt/app "}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if d := steps[4]; d.Owner != "root" || d.Group != "root" || d.Mode != "0755" || d.Name != "/opt/db" {
		t.Fatalf("directory defaults: %+v", d)
	}
}

func TestParseMarkdownSections(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbJ7hzMFs5GzG0z3zCmbXnwqiwvGrD3w1dNRz2iBV3O ops@laptop"
	src := "Base setup for the API hosts.\n\n" +
		"## Groups\n- deployers (system)\n- remove legacy\n\n" +
		"## Users\n- deploy in deployers and wheel groups, shell /bin/bash\n  - key " + key + "\n- remove olduser\n\n" +
		"## Directories\n- /srv/api owned by deploy:deployers, mode 0750\n\n" +
		"## Configuration files\n- /etc/motd\n\n  ```\n  Managed by Korta\n  ```\n- remove /etc/old.conf\n\n" +
		"## Packages\n- nginx, curl\n- keep openssl at the latest version\n- remove telnet\n\n" +
		"## Services\n- nginx running and enabled, restart on change\n- postfix stopped, disabled\n\n" +
		"## Kernel settings\n- net.core.somaxconn = 1024\n- `vm.swappiness: 10`\n\n" +
		"## Firewall\n- open 80, 443/tcp from 10.0.0.0/8 and 192.168.1.10\n- close 23 from anywhere\n\n" +
		"## Updates\n- security updates, reboot if required, except kernel\n\n" +
		"## Commands\n- Install the agent unless /opt/agent exists\n\n```sh\ncurl -fsSL https://example.com/agent | sh\n```\n- `systemctl daemon-reload`\n"
	steps, err := ParseMarkdown(src)
	if err != nil {
		t.Fatal(err)
	}
	r := Role{Name: "api", Steps: steps, Targets: Targets{Labels: map[string]string{"role": "api"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	types := []string{}
	for _, s := range steps {
		types = append(types, s.Type)
	}
	// wheel is not declared, so a group step for it comes before the user.
	want := "group group group user user directory file file packages packages packages service service sysctl firewall firewall firewall patch command command"
	if strings.Join(types, " ") != want {
		t.Fatalf("types: %s", strings.Join(types, " "))
	}
	check := func(i int, ok bool) {
		t.Helper()
		if !ok {
			t.Fatalf("step %d: %+v", i, steps[i])
		}
	}
	check(0, steps[0].Group == "deployers" && steps[0].System)
	check(1, steps[1].Group == "legacy" && steps[1].State == "absent")
	check(2, steps[2].Group == "wheel")
	check(3, steps[3].User == "deploy" && reflect.DeepEqual(steps[3].Groups, []string{"deployers", "wheel"}) && steps[3].Shell == "/bin/bash" && len(steps[3].AuthorizedKeys) == 1)
	check(4, steps[4].User == "olduser" && steps[4].State == "absent")
	check(5, steps[5].Owner == "deploy" && steps[5].Group == "deployers" && steps[5].Mode == "0750")
	check(6, steps[6].Path == "/etc/motd" && steps[6].Content == "Managed by Korta\n")
	check(7, steps[7].State == "absent" && steps[7].Path == "/etc/old.conf")
	check(8, steps[8].State == "present" && reflect.DeepEqual(steps[8].Packages, []string{"nginx", "curl"}))
	check(9, steps[9].State == "latest" && reflect.DeepEqual(steps[9].Packages, []string{"openssl"}))
	check(10, steps[10].State == "absent")
	check(11, steps[11].Service == "nginx" && steps[11].State == "started" && *steps[11].Enabled && steps[11].RestartOnChange)
	check(12, steps[12].State == "stopped" && !*steps[12].Enabled)
	check(13, steps[13].Settings["net.core.somaxconn"] == "1024" && steps[13].Settings["vm.swappiness"] == "10")
	check(14, steps[14].Port == 80 && steps[14].Protocol == "tcp" && reflect.DeepEqual(steps[14].Sources, []string{"10.0.0.0/8", "192.168.1.10/32"}))
	check(15, steps[15].Port == 443)
	check(16, steps[16].Port == 23 && steps[16].State == "closed" && len(steps[16].Sources) == 2)
	check(17, steps[17].Scope == "security" && steps[17].Reboot == "if-required" && reflect.DeepEqual(steps[17].Exclude, []string{"kernel"}))
	check(18, steps[18].Creates == "/opt/agent" && strings.HasPrefix(steps[18].Run, "curl"))
	check(19, steps[19].Run == "systemctl daemon-reload\n")
	if len(r.Risky()) != 7 {
		t.Fatalf("risks: %v", r.Risky())
	}
}

func TestParseMarkdownErrors(t *testing.T) {
	cases := map[string]string{
		"- nginx":                               "line 1: put bullets under a heading",
		"# Web servers\n- nginx":                `line 2: the section "Web servers" (line 1) does not say what it manages`,
		"# Users\n- test frobnicated":           `line 2: cannot tell what "frobnicated" means`,
		"# Files\n- /etc/motd":                  "line 2: put the content of /etc/motd in a code block",
		"# Files\n```\nx\n```":                  "line 2: put a bullet with the file path",
		"# Commands\n```\necho hi":              "line 2: the code block is not closed",
		"# Directories\n- /proc/x":              "line 2: path /proc/x is under /proc",
		"# Firewall\n- open 443":                "line 2: say who may connect",
		"# Packages\n- install nginx, remove x": "line 2: a bullet can either install, remove",
		"Just notes.":                           "the Markdown has no steps",
	}
	for src, want := range cases {
		_, err := ParseMarkdown(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
}

func TestMarkdownRoundTrip(t *testing.T) {
	yes := true
	steps := []Step{
		{Type: "group", Group: "ops", System: true},
		{Type: "user", User: "deploy", Groups: []string{"ops"}, Shell: "/bin/bash", AuthorizedKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbJ7hzMFs5GzG0z3zCmbXnwqiwvGrD3w1dNRz2iBV3O ops@laptop"}},
		{Type: "directory", Path: "/srv/app", Owner: "deploy", Group: "ops", Mode: "0750"},
		{Type: "file", Path: "/etc/motd", Content: "uses ``` fences\n\nand blank lines\n"},
		{Type: "file", Path: "/etc/empty", Content: ""},
		{Type: "packages", State: "latest", Packages: []string{"openssl", "curl"}},
		{Type: "service", Service: "nginx", Enabled: &yes, RestartOnChange: true},
		{Type: "sysctl", Settings: map[string]string{"net.ipv4.tcp_rmem": "4096 87380 6291456"}},
		{Type: "firewall", State: "closed", Port: 53, Protocol: "udp", Sources: []string{"0.0.0.0/0", "::/0"}},
		{Type: "patch", Scope: "all", Reboot: "never", Exclude: []string{"kernel", "docker-ce"}},
		{Type: "command", Run: "#!/bin/sh\necho done\n", Creates: "/var/lib/done"},
	}
	for i := range steps {
		if err := steps[i].normalize(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	md := ToMarkdown(steps)
	back, err := ParseMarkdown(md)
	if err != nil {
		t.Fatalf("%v\n%s", err, md)
	}
	for i := range back {
		back[i].Name = ""
		if err := back[i].normalize(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(back, steps) {
		t.Fatalf("round trip differs\n%s\n got %+v\nwant %+v", md, back, steps)
	}
}
