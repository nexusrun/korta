package hostnetwork

import (
	"context"
	"encoding/json"
	"fmt"
)

// Link describes one interface for choosing an interface to inspect. Only an
// interface marked Inspectable may be passed to Inspect.
type Link struct {
	Name        string   `json:"name"`
	State       string   `json:"state"`
	MTU         int      `json:"mtu"`
	MAC         string   `json:"mac,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	Inspectable bool     `json:"inspectable"`
}

// List reports every interface on the host and its addresses. It changes nothing.
func List(ctx context.Context, r Runner) ([]Link, error) {
	out, err := r.Run(ctx, "ip -json address show")
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	return ParseList(out)
}

// ParseList validates iproute2's address listing. Unsupported output is an
// error, never an empty list.
func ParseList(b []byte) ([]Link, error) {
	var rows []struct {
		Name     string `json:"ifname"`
		State    string `json:"operstate"`
		MTU      int    `json:"mtu"`
		MAC      string `json:"address"`
		AddrInfo []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(b, &rows); err != nil || rows == nil {
		return nil, fmt.Errorf("iproute2 returned invalid JSON")
	}
	links := make([]Link, 0, len(rows))
	for _, r := range rows {
		if r.Name == "" {
			return nil, fmt.Errorf("iproute2 returned an interface without a name")
		}
		l := Link{Name: r.Name, State: r.State, MTU: r.MTU, MAC: r.MAC, Inspectable: interfaceName.MatchString(r.Name)}
		for _, a := range r.AddrInfo {
			if a.Local != "" {
				l.Addresses = append(l.Addresses, fmt.Sprintf("%s/%d", a.Local, a.Prefix))
			}
		}
		links = append(links, l)
	}
	return links, nil
}
