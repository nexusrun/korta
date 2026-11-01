package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nexusrun/korta/hostnetwork"
	"github.com/nexusrun/korta/sshclient"
)

type networkResult struct {
	Host        string                   `json:"host"`
	Observation *hostnetwork.Observation `json:"observation,omitempty"`
	Error       string                   `json:"error,omitempty"`
}

// inspectNetwork queries selected inventory hosts over the normal SSH path.
// It is deliberately read-only; configuration needs a safe rollback workflow.
func (c *client) inspectNetwork(ctx context.Context) error {
	o := c.opts
	if len(o.args) != 3 || o.args[1] != "inspect" {
		return fmt.Errorf("usage: korta network inspect INTERFACE -i hosts.md [--limit SELECTOR]")
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
	sshConfig := firstOf(o.values["ssh-config"], os.Getenv("KORTA_SSH_CONFIG"))
	if sshConfig != "" {
		if _, err := os.Stat(sshConfig); err != nil {
			return fmt.Errorf("--ssh-config: %w", err)
		}
	}
	results := make([]networkResult, 0, len(hosts))
	failed := 0
	for _, h := range hosts {
		result := networkResult{Host: h.Name}
		run := sshRunner{sshclient.System{Host: h.Address, Port: h.Port, User: h.User, ConfigFile: sshConfig, IdentityFile: h.Identity}}
		obs, err := hostnetwork.Inspect(ctx, run, o.args[2])
		if err != nil {
			result.Error = err.Error()
			failed++
		} else {
			result.Observation = &obs
		}
		results = append(results, result)
	}
	b, err := json.Marshal(results)
	if err != nil {
		return err
	}
	if err = c.print(b); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("network inspection failed on %s", count(fmt.Sprint(failed), "host"))
	}
	return nil
}
