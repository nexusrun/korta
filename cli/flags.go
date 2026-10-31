package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// options holds parsed flags and the remaining positional arguments.
type options struct {
	values map[string]string
	args   []string
}

var booleanFlags = map[string]bool{
	"json": true, "wait": true, "approve": true, "confirm-commands": true, "help": true,
	"continue-on-failure": true, "insecure": true, "yes": true, "destroy": true,
}

var valueFlags = map[string]bool{
	"server": true, "token-file": true, "config": true, "timeout": true, "file": true, "data": true,
	"output": true, "role": true, "database": true, "target": true, "plan": true, "name": true,
	"private-key": true, "markdown": true, "text": true, "instance": true, "label": true,
	"description": true, "batch-size": true, "host": true, "port": true, "user": true, "key": true,
	"host-key": true, "type": true, "inventory": true, "limit": true, "ssh-config": true, "identity": true, "var": true, "value-file": true, "confirm": true,
}

// listFlags may be repeated; their values are joined with commas.
var listFlags = map[string]bool{"instance": true, "label": true, "limit": true}

func parse(args []string) (options, error) {
	o := options{values: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h":
			a = "--help"
		case "-f":
			a = "--file"
		case "-i":
			a = "--inventory"
		case "-k":
			a = "--identity"
		}
		if !strings.HasPrefix(a, "--") {
			if strings.HasPrefix(a, "-") && a != "-" {
				return o, fmt.Errorf("unknown flag %s (see korta --help)", a)
			}
			o.args = append(o.args, a)
			continue
		}
		key, val, eq := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch {
		case booleanFlags[key]:
			if !eq {
				val = "true"
			}
			v, err := strconv.ParseBool(val)
			if err != nil {
				return o, fmt.Errorf("--%s takes true or false", key)
			}
			val = strconv.FormatBool(v)
		case valueFlags[key]:
			if !eq {
				i++
				if i == len(args) {
					return o, fmt.Errorf("--%s needs a value", key)
				}
				val = args[i]
			}
		default:
			if s := closest(key, keys(booleanFlags, valueFlags)); s != "" {
				return o, fmt.Errorf("unknown flag --%s; did you mean --%s?", key, s)
			}
			return o, fmt.Errorf("unknown flag --%s (see korta --help)", key)
		}
		switch {
		case key == "var" && o.values[key] != "":
			val = o.values[key] + "\n" + val // values may contain commas
		case listFlags[key] && o.values[key] != "":
			val = o.values[key] + "," + val
		}
		o.values[key] = val
	}
	return o, nil
}

func (o options) yes(k string) bool { return o.values[k] == "true" }

// set reports whether a flag was given at all, including --wait=false.
func (o options) set(k string) bool {
	_, ok := o.values[k]
	return ok
}

// labels parses repeated or comma-separated KEY=VALUE flags.
func (o options) labels(flag string) (map[string]string, error) {
	out := map[string]string{}
	for _, label := range strings.Split(o.values[flag], ",") {
		if label = strings.TrimSpace(label); label == "" {
			continue
		}
		k, v, ok := strings.Cut(label, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("--%s takes KEY=VALUE", flag)
		}
		out[k] = v
	}
	return out, nil
}

// list parses repeated or comma-separated values.
func (o options) list(flag string) []string {
	out := []string{}
	for _, v := range strings.Split(o.values[flag], ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func keys(sets ...map[string]bool) []string {
	out := []string{}
	for _, s := range sets {
		for k := range s {
			out = append(out, k)
		}
	}
	return out
}

// closest returns the candidate within two edits of word, if any.
func closest(word string, candidates []string) string {
	best, bestDist := "", 3
	for _, c := range candidates {
		if d := distance(word, c); d < bestDist || (d == bestDist && c < best) {
			best, bestDist = c, d
		}
	}
	if bestDist > 2 || bestDist >= len(word) {
		return ""
	}
	return best
}

// distance is the Levenshtein distance between a and b.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
