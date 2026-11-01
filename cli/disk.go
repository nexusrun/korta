package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nexusrun/korta/disk"
	"github.com/nexusrun/korta/sshclient"
)

type diskResult struct {
	Host        string            `json:"host"`
	Observation *disk.Observation `json:"observation,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// inspectDisk reports the state of one explicit disk ID without changing hosts.
func (c *client) inspectDisk(ctx context.Context) error {
	o := c.opts
	if len(o.args) != 3 || o.args[1] != "inspect" {
		return fmt.Errorf("usage: korta disk inspect /dev/disk/by-id/DEVICE -i hosts.md [--limit SELECTOR]")
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
	rows := make([]diskResult, 0, len(hosts))
	failed := 0
	for _, h := range hosts {
		result := diskResult{Host: h.Name}
		run := sshRunner{sshclient.System{Host: h.Address, Port: h.Port, User: h.User, ConfigFile: config, IdentityFile: h.Identity}}
		obs, err := disk.Probe(ctx, run, o.args[2])
		if err != nil {
			failed++
			result.Error = err.Error()
		} else {
			result.Observation = &obs
		}
		rows = append(rows, result)
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err = c.print(b); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("disk inspection failed on %s", count(fmt.Sprint(failed), "host"))
	}
	return nil
}
