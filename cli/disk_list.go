package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nexusrun/korta/disk"
	"github.com/nexusrun/korta/sshclient"
)

// diskListRow is one block device on one host. Error is set when the host
// could not be listed; then the other fields are empty.
type diskListRow struct {
	Host        string `json:"host"`
	Device      string `json:"device,omitempty"`
	Size        uint64 `json:"size,omitempty"`
	Type        string `json:"type,omitempty"`
	Serial      string `json:"serial,omitempty"`
	WWN         string `json:"wwn,omitempty"`
	Mountpoints string `json:"mountpoints,omitempty"`
	StableIDs   string `json:"stableIDs,omitempty"`
	Inspectable bool   `json:"inspectable"`
	Reason      string `json:"reason,omitempty"`
	Error       string `json:"error,omitempty"`
}

// listDisks shows the block devices on selected hosts and the stable IDs that
// disk inspect accepts. It changes nothing.
func (c *client) listDisks(ctx context.Context) error {
	o := c.opts
	if len(o.args) != 2 {
		return fmt.Errorf("usage: korta disk list -i hosts.md [--limit SELECTOR]")
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
	rows := []diskListRow{}
	failed := 0
	for _, h := range hosts {
		run := sshRunner{sshclient.System{Host: h.Address, Port: h.Port, User: h.User, ConfigFile: config, IdentityFile: h.Identity}}
		devices, err := disk.List(ctx, run)
		if err != nil {
			failed++
			rows = append(rows, diskListRow{Host: h.Name, Error: err.Error()})
			continue
		}
		for _, d := range devices {
			rows = append(rows, diskListRow{
				Host: h.Name, Device: d.Device, Size: d.Size, Type: d.Type, Serial: d.Serial, WWN: d.WWN,
				Mountpoints: strings.Join(d.Mountpoints, ", "), StableIDs: strings.Join(d.StableIDs, ", "),
				Inspectable: d.Inspectable, Reason: d.Reason,
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
		return fmt.Errorf("disk listing failed on %s", count(fmt.Sprint(failed), "host"))
	}
	return nil
}
