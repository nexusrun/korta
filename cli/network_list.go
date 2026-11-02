package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nexusrun/korta/hostnetwork"
	"github.com/nexusrun/korta/sshclient"
)

// networkListRow is one interface on one host. Error is set when the host
// could not be listed; then the other fields are empty.
type networkListRow struct {
	Host        string `json:"host"`
	Interface   string `json:"interface,omitempty"`
	State       string `json:"state,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	MAC         string `json:"mac,omitempty"`
	Addresses   string `json:"addresses,omitempty"`
	Inspectable bool   `json:"inspectable"`
	Error       string `json:"error,omitempty"`
}

// listNetwork shows the interfaces on selected hosts and their addresses, so
// you can choose one for network inspect. It changes nothing.
func (c *client) listNetwork(ctx context.Context) error {
	o := c.opts
	if len(o.args) != 2 {
		return fmt.Errorf("usage: korta network list -i hosts.md [--limit SELECTOR]")
	}
	if o.set("timeout") {
		d, err := time.ParseDuration(o.values["timeout"])
		if err != nil || d <= 0 {
			return fmt.Errorf("--timeout must be a positive duration")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	hosts, err := c.inventory()
	if err != nil {
		return err
	}
	config := firstOf(o.values["ssh-config"], os.Getenv("KORTA_SSH_CONFIG"))
	if config != "" {
		if _, err := os.Stat(config); err != nil {
			return fmt.Errorf("--ssh-config: %w", err)
		}
	}
	rows := []networkListRow{}
	failed := 0
	for _, h := range hosts {
		run := sshRunner{sshclient.System{Host: h.Address, Port: h.Port, User: h.User, ConfigFile: config, IdentityFile: h.Identity}}
		links, err := hostnetwork.List(ctx, run)
		if err != nil {
			failed++
			rows = append(rows, networkListRow{Host: h.Name, Error: err.Error()})
			continue
		}
		for _, l := range links {
			rows = append(rows, networkListRow{
				Host: h.Name, Interface: l.Name, State: l.State, MTU: l.MTU, MAC: l.MAC,
				Addresses: strings.Join(l.Addresses, ", "), Inspectable: l.Inspectable,
			})
		}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err = c.print(b); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("network listing failed on %s", count(fmt.Sprint(failed), "host"))
	}
	return nil
}
