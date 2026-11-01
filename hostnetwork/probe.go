// Package hostnetwork inspects Linux network interfaces for future role plans.
// It does not apply or authorize network changes.
package hostnetwork

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
)

// Runner executes a command on the host. The caller controls SSH and privileges.
type Runner interface {
	Run(context.Context, string) ([]byte, error)
}

// Observation is a read-only snapshot of an interface and its IPv4 and IPv6
// routes. Resolver configuration and persistent network-manager profiles are
// not included, so it must not be used to authorize configuration changes.
type Observation struct {
	Interface  string          `json:"interface"`
	Addresses  json.RawMessage `json:"addresses"`
	IPv4Routes json.RawMessage `json:"ipv4Routes"`
	IPv6Routes json.RawMessage `json:"ipv6Routes"`
}

// Interface names are restricted before they are placed in shell commands.
// Linux interface names have at most 15 bytes and cannot contain shell syntax.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

// Inspect reads the interface and route state using iproute2. It never writes
// host configuration. Missing utilities, inaccessible hosts and unsupported
// output are reported instead of being treated as an empty configuration.
func Inspect(ctx context.Context, r Runner, name string) (Observation, error) {
	if !interfaceName.MatchString(name) {
		return Observation{}, fmt.Errorf("interface must be a Linux interface name of at most 15 letters, digits, underscores, dots or hyphens")
	}
	obs := Observation{Interface: name}
	queries := []struct {
		label, command string
		target         *json.RawMessage
	}{
		{"interface", "ip -json address show dev " + name, &obs.Addresses},
		{"IPv4 routes", "ip -json -4 route show dev " + name, &obs.IPv4Routes},
		{"IPv6 routes", "ip -json -6 route show dev " + name, &obs.IPv6Routes},
	}
	for _, q := range queries {
		out, err := r.Run(ctx, q.command)
		if err != nil {
			return Observation{}, fmt.Errorf("inspect %s: %w", q.label, err)
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(out, &rows); err != nil || rows == nil {
			return Observation{}, fmt.Errorf("inspect %s: iproute2 returned invalid JSON", q.label)
		}
		if q.label == "interface" && len(rows) != 1 {
			return Observation{}, fmt.Errorf("inspect interface: expected one matching interface")
		}
		*q.target = append(json.RawMessage(nil), out...)
	}
	return obs, nil
}
