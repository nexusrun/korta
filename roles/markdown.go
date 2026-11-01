package roles

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Markdown roles: each heading says what its section manages, each bullet
// describes one desired state in a short phrase, and fenced code blocks carry
// file content and scripts. For example:
//
//	# Create users
//	- test added to database group
//	- app user added to apps group
//
//	# Create directories
//	- /opt/db owned by test, mode 0750
//	- /opt/app
//
// ParseMarkdown compiles a document to typed steps and ToMarkdown writes
// steps back. Phrasing is flexible, but anything Korta does not understand is
// an error with its line number: a role never guesses.

// sectionKinds map heading words to step types. The earliest matching word
// in a heading decides, so "Create users" manages users.
var sectionKinds = []struct{ kind, prefix string }{
	{"aws-instance", "aws"},
	{"gcp-instance", "gcp"},
	{"selinux", "selinux"},
	{"scheduled-job", "scheduled"},
	{"dns", "dns"}, {"hostname", "hostname"}, {"timezone", "timezone"}, {"time", "time"},
	{"group", "group"},
	{"user", "user"}, {"user", "account"},
	{"directory", "director"}, {"directory", "folder"},
	{"packages", "package"}, {"packages", "software"},
	{"service", "service"},
	{"file", "file"},
	{"sysctl", "sysctl"}, {"sysctl", "kernel"},
	{"firewall", "firewall"}, {"firewall", "port"},
	{"patch", "patch"}, {"patch", "update"},
	{"command", "command"}, {"command", "script"},
	{"vars", "variable"}, {"vars", "vars"},
}

var sectionTitles = map[string]string{
	"gcp-instance": "GCP instance", "aws-instance": "AWS instance", "aws-network": "AWS network", "aws-lb": "AWS load balancer", "aws-dns": "AWS DNS", "time": "Time", "ntp": "Time", "dns": "DNS", "hostname": "Hostname", "timezone": "Timezone", "group": "Groups", "user": "Users", "directory": "Directories", "packages": "Packages",
	"service": "Services", "file": "Files", "sysctl": "Kernel settings", "firewall": "Firewall",
	"selinux-mode": "SELinux", "selinux-boolean": "SELinux", "selinux-port": "SELinux", "selinux-fcontext": "SELinux", "patch": "Updates", "command": "Commands", "scheduled-job": "Scheduled jobs",
}

const sectionHelp = "start its heading with SELinux, Hostname, Time, DNS, Variables, Users, Groups, Directories, Files, Packages, Services, Kernel settings, Firewall, Updates or Commands"

var (
	headingRe = regexp.MustCompile(`^(#{1,6})\s*(.*?)\s*#*$`)
	bulletRe  = regexp.MustCompile(`^(?:[-*+]|\d{1,3}[.)])\s+(.*)$`)
	fenceRe   = regexp.MustCompile("^(`{3,}|~{3,})")
	keyRe     = regexp.MustCompile(`(?:^|\s)((?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]+.*)$`)
	inlineRe  = regexp.MustCompile("`([^`]+)`")
	sysctlRe  = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*(?:=|:|\s)\s*(.+)$`)
	portRe    = regexp.MustCompile(`^(?:(tcp|udp)/)?(\d{1,5})(?:/(tcp|udp))?$`)
)

type mdItem struct {
	kind   string
	title  string
	line   int
	indent int
	text   string   // the bullet without its marker
	extra  []string // nested bullets
	code   *string
}

func (it mdItem) errorf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", it.line, fmt.Sprintf(format, args...))
}

// ParseMarkdown compiles a Markdown role to steps.
func ParseMarkdown(src string) ([]Step, error) {
	items, err := scanMarkdown(src)
	if err != nil {
		return nil, err
	}
	steps := []Step{}
	gcp, err := parseGCP(items)
	if err != nil {
		return nil, err
	}
	if gcp != nil {
		steps = append(steps, *gcp)
	}
	cloud, err := parseAWS(items)
	if err != nil {
		return nil, err
	}
	if cloud != nil && gcp != nil {
		return nil, fmt.Errorf("a role can provision only one cloud")
	}
	if cloud != nil {
		steps = append(steps, *cloud)
	}
	network, err := parseAWSNetwork(items)
	if err != nil {
		return nil, err
	}
	if network != nil && gcp != nil {
		return nil, fmt.Errorf("a role can provision only one cloud")
	}
	if network != nil {
		return []Step{*network}, nil
	}
	sysctl := -1
	for _, it := range items {
		if it.kind == "gcp-instance" || it.kind == "aws-instance" || it.kind == "aws-lb" || it.kind == "aws-dns" {
			continue
		}
		parsed, err := parseItem(it)
		if err != nil {
			return nil, err
		}
		for _, s := range parsed {
			// One sysctl file per role: merge every setting into the first step.
			if s.Type == "sysctl" && sysctl >= 0 {
				for k, v := range s.Settings {
					steps[sysctl].Settings[k] = v
				}
				continue
			}
			if s.Type == "sysctl" {
				sysctl = len(steps)
			}
			steps = append(steps, s)
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("the Markdown has no steps; add a heading such as # Users with bullets below it")
	}
	return withGroups(steps), nil
}

// scanMarkdown splits a document into section items, attaching nested
// bullets and code blocks to the bullet above them.
func scanMarkdown(src string) ([]mdItem, error) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	items := []mdItem{}
	kind, title, titleLine := "", "", 0
	awsSection, seenSection := false, map[string]bool{}
	open := -1 // index of the last item in this section that may take a code block
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], " \t")
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		n := i + 1
		if m := fenceRe.FindString(trimmed); m != "" {
			body := []string{}
			closed := false
			for i++; i < len(lines); i++ {
				l := strings.TrimRight(lines[i], "\r")
				if t := strings.TrimSpace(l); strings.HasPrefix(t, m) && strings.Trim(t, m[:1]) == "" {
					closed = true
					break
				}
				for j := 0; j < indent && strings.HasPrefix(l, " "); j++ {
					l = l[1:]
				}
				body = append(body, l)
			}
			if !closed {
				return nil, fmt.Errorf("line %d: the code block is not closed with %s", n, m)
			}
			code := ""
			if len(body) > 0 {
				code = strings.Join(body, "\n") + "\n"
			}
			switch {
			case open >= 0:
				items[open].code = &code
				open = -1
			case kind == "command":
				items = append(items, mdItem{kind: kind, title: title, line: n, code: &code})
			case kind == "file":
				return nil, fmt.Errorf("line %d: put a bullet with the file path, such as - /etc/motd, above its code block", n)
			case kind == "":
				// Code outside a managed section is documentation.
			default:
				return nil, fmt.Errorf("line %d: code blocks are only for Files and Commands sections", n)
			}
			continue
		}
		if m := headingRe.FindStringSubmatch(trimmed); m != nil && m[2] != "" && !strings.HasPrefix(m[2], "!") {
			if (kind == "gcp-instance" || kind == "aws-instance" || kind == "aws-network" || kind == "aws-lb") && open < 0 {
				return nil, fmt.Errorf("line %d: %s needs field: value bullets", titleLine, sectionTitles[kind])
			}
			kind, title, titleLine, open = headingKind(m[2]), m[2], n, -1
			if kind == "aws-lb" || kind == "aws-dns" {
				if seenSection[kind] {
					return nil, fmt.Errorf("line %d: a role can have only one %s section", n, sectionTitles[kind])
				}
				seenSection[kind] = true
			}
			if kind == "aws-instance" || kind == "aws-network" {
				if awsSection {
					return nil, fmt.Errorf("line %d: a role can have only one AWS section: an instance or a network", n)
				}
				awsSection = true
			}
			continue
		}
		m := bulletRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue // prose documents the role
		}
		text := strings.TrimSpace(m[1])
		if text == "" {
			continue
		}
		if len(items) > 0 && open >= 0 && indent > items[open].indent {
			items[open].extra = append(items[open].extra, text)
			continue
		}
		if kind == "" {
			if title == "" {
				return nil, fmt.Errorf("line %d: put bullets under a heading that says what they manage, such as # Users", n)
			}
			return nil, fmt.Errorf("line %d: the section %q (line %d) does not say what it manages; %s", n, title, titleLine, sectionHelp)
		}
		items = append(items, mdItem{kind: kind, title: title, line: n, indent: indent, text: text})
		open = len(items) - 1
	}
	if (kind == "gcp-instance" || kind == "aws-instance" || kind == "aws-network" || kind == "aws-lb") && open < 0 {
		return nil, fmt.Errorf("line %d: %s needs field: value bullets", titleLine, sectionTitles[kind])
	}
	return items, nil
}

func headingKind(heading string) string {
	best, at := "", -1
	words := strings.Fields(strings.ToLower(heading))
	// "AWS network" and "AWS VPC" are networks; other AWS headings instances.
	if len(words) > 1 && strings.HasPrefix(words[0], "aws") && (strings.HasPrefix(words[1], "network") || words[1] == "vpc") {
		return "aws-network"
	}
	if len(words) > 1 && strings.HasPrefix(words[0], "aws") && (words[1] == "load" || words[1] == "alb" || words[1] == "lb") {
		return "aws-lb"
	}
	if len(words) > 1 && strings.HasPrefix(words[0], "aws") && (words[1] == "dns" || strings.HasPrefix(words[1], "domain") || words[1] == "route53") {
		return "aws-dns"
	}
	for i, w := range words {
		w = strings.Trim(w, "`*_:,.()")
		for _, k := range sectionKinds {
			if strings.HasPrefix(w, k.prefix) && (at < 0 || i < at) {
				best, at = k.kind, i
			}
		}
		if at >= 0 {
			break
		}
	}
	return best
}

func parseItem(it mdItem) ([]Step, error) {
	if it.kind == "vars" && it.code == nil {
		return nil, nil // read by Variables before rendering
	}
	if it.code != nil && it.kind != "file" && it.kind != "command" && it.kind != "scheduled-job" {
		return nil, it.errorf("code blocks are only for Files and Commands sections")
	}
	name := stepTitle(it)
	var steps []Step
	var err error
	switch it.kind {
	case "selinux":
		steps, err = parseSELinux(it)
	case "time":
		if len(it.extra) > 0 || it.code != nil {
			return nil, it.errorf("write timezone or ntp on one bullet")
		}
		fields := strings.Fields(strings.ReplaceAll(it.text, "`", ""))
		if len(fields) != 2 {
			return nil, it.errorf("write timezone America/Phoenix or ntp enabled")
		}
		switch fields[0] {
		case "timezone":
			steps = []Step{{Type: "timezone", Timezone: fields[1]}}
		case "ntp":
			if fields[1] != "enabled" && fields[1] != "disabled" {
				return nil, it.errorf("ntp must be enabled or disabled")
			}
			enabled := fields[1] == "enabled"
			steps = []Step{{Type: "ntp", NTP: &enabled}}
		default:
			return nil, it.errorf("use timezone or ntp")
		}
	case "dns":
		if len(it.extra) > 0 || it.code != nil {
			return nil, it.errorf("write nameservers on one bullet")
		}
		value := strings.TrimSpace(strings.ReplaceAll(it.text, "`", ""))
		key, rest, ok := strings.Cut(value, " ")
		if !ok || (key != "nameservers" && key != "nameserver") {
			return nil, it.errorf("write nameservers followed by 1-3 IP addresses")
		}
		steps = []Step{{Type: "dns", Nameservers: strings.Fields(strings.ReplaceAll(rest, ",", " "))}}
	case "hostname", "timezone":
		if len(it.extra) > 0 || it.code != nil {
			return nil, it.errorf("write a single value on the bullet")
		}
		value := strings.TrimSpace(strings.ReplaceAll(it.text, "`", ""))
		if it.kind == "hostname" {
			steps = []Step{{Type: "hostname", Hostname: value}}
		} else {
			steps = []Step{{Type: "timezone", Timezone: value}}
		}
	case "group":
		steps, err = parseGroup(it)
	case "user":
		steps, err = parseUser(it)
	case "directory", "file":
		steps, err = parsePath(it)
	case "packages":
		steps, err = parsePackages(it)
	case "service":
		steps, err = parseService(it)
	case "sysctl":
		steps, err = parseSysctl(it)
	case "firewall":
		steps, err = parseFirewall(it)
	case "patch":
		steps, err = parsePatch(it)
	case "scheduled-job":
		steps, err = parseScheduledJob(it)
	case "command":
		steps, err = parseCommand(it)
	}
	if err != nil {
		return nil, err
	}
	for i := range steps {
		if steps[i].Name == "" {
			steps[i].Name = name
		}
		if err := steps[i].normalize(); err != nil {
			return nil, it.errorf("%v", err)
		}
	}
	return steps, nil
}

// withGroups creates the groups that users join before those users, unless
// an earlier step already manages them.
func withGroups(steps []Step) []Step {
	known := map[string]bool{}
	out := []Step{}
	for _, s := range steps {
		switch s.Type {
		case "group":
			known[s.Group] = true
		case "user":
			if s.State == "present" {
				for _, g := range s.Groups {
					if !known[g] {
						out = append(out, Step{Type: "group", Name: "Group " + g, Group: g, State: "present"})
						known[g] = true
					}
				}
				known[s.User] = true
			}
		}
		out = append(out, s)
	}
	return out
}

func stepTitle(it mdItem) string {
	t := strings.TrimSpace(strings.NewReplacer("`", "", "**", "", "__", "").Replace(it.text))
	if t == "" {
		t = it.title
	}
	if len(t) > 120 {
		t = strings.TrimSpace(t[:117]) + "..."
	}
	return t
}

// words splits a phrase into tokens, dropping list punctuation and
// Markdown emphasis but keeping paths, owners such as app:apps and CIDRs.
func words(s string) []string {
	s = strings.NewReplacer(",", " ", ";", " ", "`", " ", "**", " ", "(", " ", ")", " ").Replace(s)
	out := []string{}
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, `"'*_[]`)
		w = strings.TrimRight(w, ".:!")
		if len(w) > 1 && strings.HasPrefix(w, "/") {
			w = strings.TrimRight(w, "/")
		}
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

func set(words ...string) map[string]bool {
	m := map[string]bool{}
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	removeWords = set("remove", "removed", "delete", "deleted", "absent", "uninstall", "uninstalled", "drop")
	createWords = set("create", "created", "add", "make", "ensure", "present", "exists", "exist", "new")
	fillerWords = set("a", "an", "the", "and", "with", "is", "are", "be", "should", "must", "also", "it", "that", "as")
)

func parseGroup(it mdItem) ([]Step, error) {
	s := Step{Type: "group", State: "present"}
	for _, w := range words(strings.Join(append([]string{it.text}, it.extra...), " ")) {
		l := strings.ToLower(w)
		switch {
		case removeWords[l]:
			s.State = "absent"
		case l == "system":
			s.System = true
		case createWords[l] || fillerWords[l] || l == "group" || l == "groups":
		case s.Group == "":
			s.Group = w
		default:
			return nil, it.errorf("cannot tell what %q means; write a group name, optionally (system), or remove NAME", w)
		}
	}
	if s.Group == "" {
		return nil, it.errorf("name the group")
	}
	return []Step{s}, nil
}

var joinWords = set("added", "joins", "join", "joined", "in", "into", "member", "members", "of", "to", "group", "groups", "supplementary", "secondary")

func parseUser(it mdItem) ([]Step, error) {
	s := Step{Type: "user", State: "present"}
	rest := []string{}
	for _, l := range append([]string{it.text}, it.extra...) {
		l = strings.ReplaceAll(l, "`", "")
		if loc := keyRe.FindStringSubmatchIndex(l); loc != nil {
			s.AuthorizedKeys = append(s.AuthorizedKeys, strings.TrimSpace(l[loc[2]:loc[3]]))
			l = l[:loc[2]]
		}
		rest = append(rest, l)
	}
	toks := words(strings.Join(rest, " "))
	inGroups := false
	for i := 0; i < len(toks); i++ {
		w, l := toks[i], strings.ToLower(toks[i])
		switch {
		case removeWords[l]:
			s.State = "absent"
		case s.User == "" && (createWords[l] || l == "user" || l == "account"):
		case s.User == "":
			s.User = w
		case l == "shell":
			if i+1 >= len(toks) {
				return nil, it.errorf("shell needs a path such as /bin/bash")
			}
			i++
			s.Shell, inGroups = toks[i], false
		case l == "key" || l == "keys" || l == "ssh" || l == "authorized":
		case joinWords[l]:
			inGroups = true
		case fillerWords[l] || l == "user" || l == "account" || createWords[l]:
		case inGroups:
			if !contains(s.Groups, w) {
				s.Groups = append(s.Groups, w)
			}
		default:
			return nil, it.errorf("cannot tell what %q means; write a user name, then for example: added to NAME group, shell /bin/bash, key ssh-ed25519 ...", w)
		}
	}
	if s.User == "" {
		return nil, it.errorf("name the user")
	}
	return []Step{s}, nil
}

// parsePath handles directories and files: a path with optional owner,
// group and mode, and for files a code block with the content.
func parsePath(it mdItem) ([]Step, error) {
	s := Step{Type: it.kind, State: "present"}
	// "check with COMMAND" takes the rest of the line, commas included.
	text := it.text
	if i := strings.Index(strings.ToLower(text), "check with "); i >= 0 {
		if it.kind != "file" {
			return nil, it.errorf("only files can have a check command")
		}
		s.Check = strings.Trim(strings.TrimSpace(text[i+len("check with "):]), "`")
		text = strings.TrimRight(strings.TrimSpace(text[:i]), ",")
		if s.Check == "" {
			return nil, it.errorf("write the command after check with, such as check with nginx -t")
		}
	}
	toks := words(strings.Join(append([]string{text}, it.extra...), " "))
	next := func(i *int, what string) (string, error) {
		if *i+1 >= len(toks) {
			return "", it.errorf("%s needs a value", what)
		}
		*i++
		return toks[*i], nil
	}
	for i := 0; i < len(toks); i++ {
		w, l := toks[i], strings.ToLower(toks[i])
		var err error
		switch {
		case removeWords[l]:
			s.State = "absent"
		case strings.HasPrefix(w, "/") && s.Path == "":
			s.Path = w
		case l == "owned" || l == "by" || l == "owner":
			if l == "owned" && i+1 < len(toks) && strings.EqualFold(toks[i+1], "by") {
				i++
			}
			var v string
			if v, err = next(&i, "owner"); err == nil {
				s.Owner, s.Group, _ = strings.Cut(v, ":")
			}
		case l == "group":
			s.Group, err = next(&i, "group")
		case l == "mode" || l == "permissions" || l == "perms" || l == "chmod":
			s.Mode, err = next(&i, "mode")
		case modePattern.MatchString(w):
			s.Mode = w
		case l == "from" && it.kind == "file":
			s.Source, err = next(&i, "from")
			if err == nil {
				err = checkSource(s.Source)
			}
		case l == "raw" && it.kind == "file":
			s.Raw = true
		case strings.Contains(w, ":") && !strings.HasPrefix(w, "/"):
			s.Owner, s.Group, _ = strings.Cut(w, ":")
		case createWords[l] || fillerWords[l] || l == "directory" || l == "directories" || l == "folder" || l == "file" || l == "content" || l == "contents" || l == "below":
		default:
			return nil, it.errorf("cannot tell what %q means; write a path, then for example: owned by app:apps, mode 0750", w)
		}
		if err != nil {
			return nil, err
		}
	}
	if s.Path == "" {
		return nil, it.errorf("start the bullet with an absolute path such as /opt/app")
	}
	if it.kind == "file" {
		switch {
		case s.Source != "" && it.code != nil:
			return nil, it.errorf("give %s either a code block or from FILE, not both", s.Path)
		case s.Raw && s.Source == "":
			return nil, it.errorf("raw goes with from FILE; mark a code block raw after its language instead")
		case s.State == "present" && it.code == nil && s.Source == "":
			return nil, it.errorf("put the content of %s in a code block below the bullet, or write from templates/FILE", s.Path)
		case s.State == "absent" && (it.code != nil || s.Source != ""):
			return nil, it.errorf("a file being removed has no content")
		case it.code != nil:
			s.Content = *it.code
		}
	}
	return []Step{s}, nil
}

func parsePackages(it mdItem) ([]Step, error) {
	s := Step{Type: "packages"}
	state := func(v string) error {
		if s.State != "" && s.State != v {
			return it.errorf("a bullet can either install, remove or keep packages latest; split it into several bullets")
		}
		s.State = v
		return nil
	}
	for _, w := range words(strings.Join(append([]string{it.text}, it.extra...), " ")) {
		l := strings.ToLower(w)
		var err error
		switch {
		case l == "install" || l == "installed" || l == "add":
			err = state("present")
		case removeWords[l]:
			err = state("absent")
		case l == "latest" || l == "upgrade" || l == "upgraded" || l == "updated" || l == "current" || l == "newest" || l == "up-to-date":
			err = state("latest")
		case fillerWords[l] || l == "package" || l == "packages" || l == "keep" || l == "at" || l == "version" || l == "versions" || l == "always" || l == "to" || l == "up" || l == "date":
		default:
			if !contains(s.Packages, w) {
				s.Packages = append(s.Packages, w)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if len(s.Packages) == 0 {
		return nil, it.errorf("name the packages, such as nginx, curl")
	}
	if s.State == "" {
		s.State = "present"
	}
	return []Step{s}, nil
}

func parseService(it mdItem) ([]Step, error) {
	s := Step{Type: "service"}
	for _, w := range words(strings.Join(append([]string{it.text}, it.extra...), " ")) {
		l := strings.ToLower(w)
		t, f := true, false
		switch {
		case l == "start" || l == "started" || l == "running" || l == "run" || l == "up":
			s.State = "started"
		case l == "stop" || l == "stopped" || l == "down":
			s.State = "stopped"
		case l == "enable" || l == "enabled":
			s.Enabled = &t
		case l == "disable" || l == "disabled":
			s.Enabled = &f
		case l == "restart" || l == "restarted":
			s.RestartOnChange = true
		case l == "reload" || l == "reloaded":
			s.ReloadOnChange = true
		case fillerWords[l] || l == "service" || l == "at" || l == "boot" || l == "on" || l == "when" || l == "if" || l == "change" || l == "changes" || l == "changed" || l == "something" || l == "keep" || l == "always":
		case s.Service == "":
			s.Service = w
		default:
			return nil, it.errorf("cannot tell what %q means; write a service name, then for example: started, enabled, reload on change", w)
		}
	}
	if s.Service == "" {
		return nil, it.errorf("name the service")
	}
	return []Step{s}, nil
}

func parseSysctl(it mdItem) ([]Step, error) {
	s := Step{Type: "sysctl", Name: it.title, Settings: map[string]string{}}
	for _, l := range append([]string{it.text}, it.extra...) {
		m := sysctlRe.FindStringSubmatch(strings.TrimSpace(strings.ReplaceAll(l, "`", "")))
		if m == nil {
			return nil, it.errorf("write kernel settings as name = value, such as net.core.somaxconn = 1024")
		}
		s.Settings[m[1]] = strings.TrimSpace(m[2])
	}
	return []Step{s}, nil
}

func parseFirewall(it mdItem) ([]Step, error) {
	state, proto := "", ""
	ports, sources := []int{}, []string{}
	for _, w := range words(strings.Join(append([]string{it.text}, it.extra...), " ")) {
		l := strings.ToLower(w)
		switch {
		case l == "open" || l == "allow" || l == "allowed" || l == "accept":
			state = "open"
		case l == "close" || l == "closed" || l == "deny" || l == "block" || removeWords[l]:
			state = "closed"
		case l == "tcp" || l == "udp":
			proto = l
		case l == "anywhere" || l == "everyone" || l == "any":
			sources = append(sources, "0.0.0.0/0", "::/0")
		case portRe.MatchString(l):
			m := portRe.FindStringSubmatch(l)
			p, _ := strconv.Atoi(m[2])
			ports = append(ports, p)
			if m[1]+m[3] != "" {
				proto = m[1] + m[3]
			}
		case fillerWords[l] || l == "port" || l == "ports" || l == "from" || l == "for" || l == "to" || l == "access" || l == "traffic" || l == "incoming" || l == "on":
		default:
			if p, err := netip.ParsePrefix(w); err == nil {
				sources = append(sources, p.Masked().String())
			} else if a, err := netip.ParseAddr(w); err == nil {
				sources = append(sources, netip.PrefixFrom(a, a.BitLen()).String())
			} else {
				return nil, it.errorf("cannot tell what %q means; write for example: open 443/tcp from 10.0.0.0/8", w)
			}
		}
	}
	if len(ports) == 0 {
		return nil, it.errorf("name the port, such as 443/tcp")
	}
	if len(sources) == 0 {
		return nil, it.errorf("say who may connect, such as from 10.0.0.0/8 or from anywhere")
	}
	steps := []Step{}
	for _, p := range ports {
		steps = append(steps, Step{Type: "firewall", State: state, Port: p, Protocol: proto, Sources: append([]string(nil), sources...)})
	}
	return steps, nil
}

func parsePatch(it mdItem) ([]Step, error) {
	s := Step{Type: "patch"}
	toks := words(strings.Join(append([]string{it.text}, it.extra...), " "))
	excluding, rebootSaid, negate := false, false, false
	for i := 0; i < len(toks); i++ {
		w, l := toks[i], strings.ToLower(toks[i])
		switch {
		case l == "except" || l == "exclude" || l == "excluding" || l == "but":
			excluding = true
		case excluding && !(l == "reboot" || l == "and" || l == "packages" || l == "package"):
			s.Exclude = append(s.Exclude, w)
		case l == "security":
			s.Scope = "security"
		case l == "all" || l == "everything":
			s.Scope = "all"
		case l == "no" || l == "never" || l == "without" || l == "don't" || l == "not":
			if rebootSaid {
				s.Reboot = "never"
			}
			negate = true
		case l == "reboot" || l == "reboots" || l == "rebooting" || l == "restart":
			excluding, rebootSaid = false, true
			if negate {
				s.Reboot = "never"
			}
		case rebootSaid && l == "always":
			s.Reboot = "always"
		case rebootSaid && (l == "required" || l == "needed" || l == "necessary"):
			s.Reboot = "if-required"
		case fillerWords[l] || l == "updates" || l == "update" || l == "patches" || l == "patch" || l == "install" || l == "apply" || l == "only" || l == "packages" || l == "os" || l == "if" || l == "when" || l == "is":
		default:
			return nil, it.errorf("cannot tell what %q means; write for example: security updates, reboot if required, except kernel", w)
		}
	}
	if rebootSaid && s.Reboot == "" {
		s.Reboot = "always"
	}
	return []Step{s}, nil
}

func parseCommand(it mdItem) ([]Step, error) {
	s := Step{Type: "command"}
	text := it.text
	if m := inlineRe.FindStringSubmatch(text); m != nil && it.code == nil && len(it.extra) == 0 {
		s.Run = m[1] + "\n"
		text = strings.Replace(text, m[0], "", 1)
	}
	if it.code != nil {
		s.Run = *it.code
	}
	toks := words(text)
	for i := 0; i+1 < len(toks); i++ {
		if l := strings.ToLower(toks[i]); (l == "unless" || l == "creates" || l == "creating") && strings.HasPrefix(toks[i+1], "/") {
			s.Creates = toks[i+1]
		}
	}
	if strings.TrimSpace(s.Run) == "" {
		return nil, it.errorf("put the script in a code block below the bullet, or write it as `inline code`")
	}
	if it.text == "" || strings.TrimSpace(text) == "" {
		s.Name = "Run script"
	}
	return []Step{s}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ToMarkdown writes steps as a Markdown role that compiles back to the same
// steps (step names come from the bullets).
func ToMarkdown(steps []Step) string {
	var b strings.Builder
	prev := ""
	for _, s := range steps {
		if s.Type != prev {
			if prev != "" {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "# %s\n\n", sectionTitles[s.Type])
			prev = s.Type
		}
		switch s.Type {
		case "aws-network":
			if s.Network != nil {
				b.WriteString(s.Network.markdown())
			}
		case "gcp-instance":
			if g := s.GCP; g != nil {
				for _, field := range [][2]string{{"name", g.Name}, {"count", strconv.Itoa(g.Count)}, {"project", g.Project}, {"zone", g.Zone}, {"size", g.MachineType}, {"image-project", g.ImageProject}, {"image-family", g.ImageFamily}, {"subnet-project", g.SubnetProject}, {"subnet", g.Subnet}, {"user", g.User}, {"address", g.Address}} {
					fmt.Fprintf(&b, "- %s: %s\n", field[0], field[1])
				}
			}
		case "aws-instance":
			a := s.AWS
			if a != nil {
				count := ""
				if a.Count > 1 {
					count = strconv.Itoa(a.Count)
				}
				for _, f := range [][2]string{{"name", a.Name}, {"count", count}, {"os", a.OS}, {"size", a.InstanceType}, {"network", a.Network}, {"region", a.Region}, {"address", a.Address}, {"static ip", map[bool]string{true: "yes"}[a.StaticIP]},
					{"image", a.Image}, {"subnet", a.Subnet}, {"security-groups", strings.Join(a.SecurityGroups, ", ")}, {"key-pair", a.KeyPair}, {"ssh-key", a.SSHKey}, {"user", a.User}} {
					if f[1] != "" {
						fmt.Fprintf(&b, "- %s: %s\n", f[0], f[1])
					}
				}
				if a.LoadBalancer != nil {
					b.WriteString("\n# AWS load balancer\n\n" + a.LoadBalancer.markdown())
				}
				if len(a.DNS) > 0 {
					b.WriteString("\n# AWS DNS\n\n- " + strings.Join(a.DNS, "\n- ") + "\n")
				}
			}
		case "selinux-mode":
			fmt.Fprintf(&b, "- mode %s\n", s.SELinuxMode)
		case "selinux-boolean":
			value := "off"
			if s.Enabled != nil && *s.Enabled {
				value = "on"
			}
			fmt.Fprintf(&b, "- boolean %s %s\n", s.SELinuxBoolean, value)
		case "selinux-port":
			fmt.Fprintf(&b, "- port %s %d %s\n", s.Protocol, s.Port, s.SELinuxType)
		case "selinux-fcontext":
			fmt.Fprintf(&b, "- fcontext %s %s", s.Path, s.SELinuxType)
			if s.Recursive {
				b.WriteString(" recursive")
			}
			b.WriteByte('\n')
		case "ntp":
			if s.NTP != nil {
				state := "disabled"
				if *s.NTP {
					state = "enabled"
				}
				fmt.Fprintf(&b, "- ntp %s\n", state)
			}
		case "dns":
			fmt.Fprintf(&b, "- nameservers %s\n", strings.Join(s.Nameservers, ", "))
		case "hostname":
			fmt.Fprintf(&b, "- %s\n", s.Hostname)
		case "timezone":
			fmt.Fprintf(&b, "- %s\n", s.Timezone)
		case "group":
			switch {
			case s.State == "absent":
				fmt.Fprintf(&b, "- remove %s\n", s.Group)
			case s.System:
				fmt.Fprintf(&b, "- %s (system)\n", s.Group)
			default:
				fmt.Fprintf(&b, "- %s\n", s.Group)
			}
		case "user":
			if s.State == "absent" {
				fmt.Fprintf(&b, "- remove %s\n", s.User)
				break
			}
			b.WriteString("- " + s.User)
			if len(s.Groups) > 0 {
				b.WriteString(", groups " + strings.Join(s.Groups, ", "))
			}
			if s.Shell != "" {
				b.WriteString(", shell " + s.Shell)
			}
			b.WriteString("\n")
			for _, k := range s.AuthorizedKeys {
				b.WriteString("  - key " + k + "\n")
			}
		case "directory", "file":
			if s.State == "absent" {
				fmt.Fprintf(&b, "- remove %s\n", s.Path)
				break
			}
			fmt.Fprintf(&b, "- %s, owner %s:%s, mode %s", s.Path, s.Owner, s.Group, s.Mode)
			if s.Source != "" {
				b.WriteString(", from " + s.Source)
				if s.Raw {
					b.WriteString(", raw")
				}
			}
			if s.Check != "" {
				b.WriteString(", check with " + s.Check)
			}
			b.WriteString("\n")
			if s.Type == "file" && s.Source == "" {
				writeFence(&b, s.Content, "")
			}
		case "packages":
			verb := map[string]string{"present": "install", "absent": "remove", "latest": "latest"}[s.State]
			fmt.Fprintf(&b, "- %s %s\n", verb, strings.Join(s.Packages, ", "))
		case "service":
			b.WriteString("- " + s.Service + " " + s.State)
			if s.Enabled != nil {
				b.WriteString(map[bool]string{true: ", enabled", false: ", disabled"}[*s.Enabled])
			}
			if s.RestartOnChange {
				b.WriteString(", restart on change")
			}
			if s.ReloadOnChange {
				b.WriteString(", reload on change")
			}
			b.WriteString("\n")
		case "sysctl":
			keys := make([]string, 0, len(s.Settings))
			for k := range s.Settings {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "- %s = %s\n", k, s.Settings[k])
			}
		case "firewall":
			verb := map[string]string{"open": "open", "closed": "close"}[s.State]
			fmt.Fprintf(&b, "- %s %d/%s from %s\n", verb, s.Port, s.Protocol, strings.Join(s.Sources, ", "))
		case "patch":
			fmt.Fprintf(&b, "- %s updates, reboot %s", s.Scope, strings.ReplaceAll(s.Reboot, "-", " "))
			if len(s.Exclude) > 0 {
				b.WriteString(", except " + strings.Join(s.Exclude, ", "))
			}
			b.WriteString("\n")
		case "scheduled-job":
			fmt.Fprintf(&b, "- %s\n", s.Job)
			if s.State == "absent" {
				b.WriteString("  - state: absent\n")
			} else {
				fmt.Fprintf(&b, "  - schedule: %s\n  - user: %s\n", s.Schedule, s.User)
				writeFence(&b, s.Run, "sh")
			}
		case "command":
			b.WriteString("- Run script")
			if s.Creates != "" {
				b.WriteString(" unless " + s.Creates + " exists")
			}
			b.WriteString("\n")
			writeFence(&b, s.Run, "sh")
		}
	}
	return b.String()
}

// writeFence writes content in a code block whose fence is longer than any
// run of backticks inside it.
func writeFence(b *strings.Builder, content, lang string) {
	fence, run := 3, 0
	for _, c := range content {
		if c == '`' {
			run++
			fence = max(fence, run+1)
		} else {
			run = 0
		}
	}
	f := strings.Repeat("`", fence)
	b.WriteString("\n" + f + lang + "\n")
	if content != "" {
		b.WriteString(strings.TrimSuffix(content, "\n") + "\n")
	}
	b.WriteString(f + "\n\n")
}
