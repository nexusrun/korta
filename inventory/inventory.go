// Package inventory reads hosts from a Markdown file, for running roles
// without a manager:
//
//	# Databases
//	- db1 ubuntu@10.0.0.5 env=prod
//	- db2 ubuntu@10.0.0.6:2222 env=prod
//
//	# Web
//	- web1 deploy@web1.internal env=staging
//	- web2.internal
//
// Headings are groups, nested by level. Each bullet is a host: an optional
// name, the SSH address as [user@]host[:port], and KEY=VALUE labels. A bullet
// with only an address, or an alias from ~/.ssh/config, uses it as the name.
//
// A "user:" or "identity:" line sets the SSH user or private key file for the
// hosts that follow in its group and subgroups, or for every host when it
// comes before the first heading:
//
//	# Production
//	identity: ~/.ssh/prod_ed25519
//	user: ubuntu
//	- db1 10.0.0.5
//	- db2 10.0.0.6 identity=~/.ssh/db2_key
//
// A host's own user@ or identity= wins over its group's.
//
// Labels are also the variables roles use as {{ name }}. A "vars:" line sets
// them for a group, and a host's own KEY=VALUE wins:
//
//	# Shop
//	vars: domain=shop.example.com app_port=3000
//	- web1 deploy@10.0.0.5
//	- web2 deploy@10.0.0.6 app_port=4000 title="Shop two"
//
// Quote values that contain spaces or commas. Other text is notes.
package inventory

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Host is one inventory entry.
type Host struct {
	Name    string            `json:"name"`
	User    string            `json:"user,omitempty"` // empty: ~/.ssh/config or the local user
	Address string            `json:"address"`
	Port    int               `json:"port,omitempty"` // 0: ~/.ssh/config or 22
	Labels  map[string]string `json:"labels,omitempty"`
	Groups  []string          `json:"groups,omitempty"`
	// Identity is the private key file as written, before ~ and ${VAR}
	// are expanded on the machine that runs korta.
	Identity string `json:"identity,omitempty"`
	Line     int    `json:"line"`
}

var (
	headingRe   = regexp.MustCompile(`^(#{1,6})\s*(.*?)\s*#*$`)
	bulletRe    = regexp.MustCompile(`^(?:[-*+]|\d{1,3}[.)])\s+(.*)$`)
	fenceRe     = regexp.MustCompile("^(`{3,}|~{3,})")
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)
	labelKey    = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,63}$`)
	settingRe   = regexp.MustCompile(`(?i)^(identity|user|vars)\s*:\s*(.*)$`)
	identityRe  = regexp.MustCompile(`^[A-Za-z0-9._/~${}+@-]{1,1000}$`)
)

// settings are the group defaults in effect at one heading level.
type settings struct {
	user, identity string
	vars           map[string]string // never modified in place: scopes share it
}

// Parse reads a Markdown inventory. Mistakes are reported with their line.
func Parse(src string) ([]Host, error) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	hosts := []Host{}
	seen := map[string]int{}
	var groups []string // heading text per level, 1-6
	levels := []int{}
	scopes := []settings{{}} // scopes[0] applies to the whole file
	last := -1               // index of the last host, for nested label bullets
	lastIndent := 0
	fence := ""
	for i, raw := range lines {
		n := i + 1
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, fence[:1]) == "" {
				fence = ""
			}
			continue
		}
		if m := fenceRe.FindString(trimmed); m != "" {
			fence = m
			continue
		}
		if m := headingRe.FindStringSubmatch(trimmed); m != nil && m[2] != "" {
			level := len(m[1])
			for len(levels) > 0 && levels[len(levels)-1] >= level {
				levels, groups, scopes = levels[:len(levels)-1], groups[:len(groups)-1], scopes[:len(scopes)-1]
			}
			levels, groups = append(levels, level), append(groups, strings.Trim(m[2], "`*_ "))
			scopes = append(scopes, scopes[len(scopes)-1])
			last = -1
			continue
		}
		if m := settingRe.FindStringSubmatch(strings.Trim(trimmed, "`*_")); m != nil {
			value := strings.Trim(strings.TrimSpace(m[2]), "`")
			scope := &scopes[len(scopes)-1]
			switch strings.ToLower(m[1]) {
			case "user":
				if !userPattern.MatchString(value) {
					return nil, fmt.Errorf("line %d: invalid SSH user %q", n, value)
				}
				scope.user = value
			case "identity":
				if !identityRe.MatchString(value) {
					return nil, fmt.Errorf("line %d: identity must be a private key file path, such as ~/.ssh/prod_ed25519", n)
				}
				scope.identity = value
			case "vars":
				var group Host
				if err := addLabels(&group, tokenize(m[2]), n); err != nil {
					return nil, err
				}
				if group.Identity != "" {
					return nil, fmt.Errorf("line %d: set a group's key with an identity: line", n)
				}
				merged := map[string]string{}
				for k, v := range scope.vars {
					merged[k] = v
				}
				for k, v := range group.Labels {
					merged[k] = v
				}
				scope.vars = merged
			}
			last = -1
			continue
		}
		m := bulletRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		tokens := tokenize(m[1])
		if len(tokens) == 0 {
			continue
		}
		if last >= 0 && indent > lastIndent {
			// A nested bullet adds labels to the host above it.
			if err := addLabels(&hosts[last], tokens, n); err != nil {
				return nil, err
			}
			continue
		}
		h, err := parseHost(tokens, n)
		if err != nil {
			return nil, err
		}
		h.Groups = append([]string(nil), groups...)
		scope := scopes[len(scopes)-1]
		if h.User == "" {
			h.User = scope.user
		}
		if h.Identity == "" {
			h.Identity = scope.identity
		}
		for k, v := range scope.vars {
			if _, own := h.Labels[k]; !own {
				h.Labels[k] = v
			}
		}
		if prev, dup := seen[strings.ToLower(h.Name)]; dup {
			return nil, fmt.Errorf("line %d: %s is already listed on line %d; give each host a unique name", n, h.Name, prev)
		}
		seen[strings.ToLower(h.Name)] = n
		hosts = append(hosts, h)
		last, lastIndent = len(hosts)-1, indent
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("the inventory lists no hosts; add bullets such as - db1 ubuntu@10.0.0.5")
	}
	return hosts, nil
}

func parseHost(tokens []string, line int) (Host, error) {
	h := Host{Line: line, Labels: map[string]string{}}
	rest := tokens
	switch {
	case len(tokens) >= 2 && !strings.Contains(tokens[1], "=") && !looksLikeAddress(tokens[0]):
		h.Name, rest = tokens[0], tokens[2:]
		if err := h.setAddress(tokens[1], line); err != nil {
			return h, err
		}
	default:
		if strings.Contains(tokens[0], "=") {
			return h, fmt.Errorf("line %d: start the bullet with the host, such as - db1 ubuntu@10.0.0.5", line)
		}
		if err := h.setAddress(tokens[0], line); err != nil {
			return h, err
		}
		h.Name, rest = h.Address, tokens[1:]
	}
	if !namePattern.MatchString(h.Name) {
		return h, fmt.Errorf("line %d: host name %q may only contain letters, digits, '.', '_' and '-'", line, h.Name)
	}
	return h, addLabels(&h, rest, line)
}

func looksLikeAddress(t string) bool {
	if strings.ContainsAny(t, "@:[") {
		return true
	}
	_, err := netip.ParseAddr(t)
	return err == nil
}

// setAddress reads [user@]host[:port], with IPv6 hosts in brackets.
func (h *Host) setAddress(s string, line int) error {
	if user, rest, ok := strings.Cut(s, "@"); ok {
		if !userPattern.MatchString(user) {
			return fmt.Errorf("line %d: invalid SSH user %q", line, user)
		}
		h.User, s = user, rest
	}
	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return fmt.Errorf("line %d: close the IPv6 address with ], such as [fd00::5]:22", line)
		}
		host, port = s[1:end], strings.TrimPrefix(s[end+1:], ":")
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("line %d: %q is not an IPv6 address", line, host)
		}
	} else if strings.Count(s, ":") == 1 {
		host, port, _ = strings.Cut(s, ":")
	} else if strings.Contains(s, ":") {
		return fmt.Errorf("line %d: write IPv6 addresses in brackets, such as [%s]", line, s)
	}
	if !strings.HasPrefix(s, "[") && !hostPattern.MatchString(host) {
		return fmt.Errorf("line %d: %q is not a host name or IP address", line, host)
	}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("line %d: port %q must be 1-65535", line, port)
		}
		h.Port = p
	}
	h.Address = host
	return nil
}

// tokenize splits on spaces and commas, keeping "quoted values" whole and
// dropping the quotes and Markdown code marks.
func tokenize(s string) []string {
	out := []string{}
	var cur strings.Builder
	quoted, any := false, false
	flush := func() {
		if any {
			out = append(out, cur.String())
		}
		cur.Reset()
		any = false
	}
	for _, r := range s {
		switch {
		case r == '"':
			quoted, any = !quoted, true
		case quoted:
			cur.WriteRune(r)
		case r == '`':
		case r == ' ' || r == '\t' || r == ',':
			flush()
		default:
			cur.WriteRune(r)
			any = true
		}
	}
	flush()
	return out
}

func addLabels(h *Host, tokens []string, line int) error {
	for _, t := range tokens {
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return fmt.Errorf("line %d: cannot tell what %q means; after the address, write labels as KEY=VALUE", line, t)
		}
		// identity= is the host's private key file, not a label.
		if k == "identity" {
			if !identityRe.MatchString(v) {
				return fmt.Errorf("line %d: identity must be a private key file path, such as ~/.ssh/db_ed25519", line)
			}
			h.Identity = v
			continue
		}
		if !labelKey.MatchString(k) {
			return fmt.Errorf("line %d: the name in %q may only contain letters, digits, '.', '_', '/' and '-'", line, t)
		}
		if v == "" || len(v) > 1000 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("line %d: %s needs a value of at most 1000 characters; quote values with spaces", line, k)
		}
		if h.Labels == nil {
			h.Labels = map[string]string{}
		}
		h.Labels[k] = v
	}
	return nil
}

// Select keeps the hosts matching any comma-separated selector: a group
// heading, a host name, or KEY=VALUE label. An empty limit keeps all hosts.
// A selector that matches nothing is an error, which catches typos.
func Select(hosts []Host, limit string) ([]Host, error) {
	selectors := []string{}
	for _, s := range strings.Split(limit, ",") {
		if s = strings.TrimSpace(s); s != "" {
			selectors = append(selectors, s)
		}
	}
	if len(selectors) == 0 {
		return hosts, nil
	}
	picked := map[int]bool{}
	for _, sel := range selectors {
		found := false
		for i, h := range hosts {
			if h.Matches(sel) {
				picked[i], found = true, true
			}
		}
		if !found {
			return nil, fmt.Errorf("--limit %s matches no host; use a group heading, a host name or KEY=VALUE (groups: %s)", sel, strings.Join(Groups(hosts), ", "))
		}
	}
	out := []Host{}
	for i, h := range hosts {
		if picked[i] {
			out = append(out, h)
		}
	}
	return out, nil
}

// Matches reports whether a selector picks this host.
func (h Host) Matches(sel string) bool {
	if k, v, ok := strings.Cut(sel, "="); ok {
		return h.Labels[k] == v
	}
	if strings.EqualFold(h.Name, sel) {
		return true
	}
	for _, g := range h.Groups {
		if strings.EqualFold(g, sel) {
			return true
		}
	}
	return false
}

// Groups lists every group heading in the inventory.
func Groups(hosts []Host) []string {
	set := map[string]bool{}
	for _, h := range hosts {
		for _, g := range h.Groups {
			set[g] = true
		}
	}
	out := []string{}
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
