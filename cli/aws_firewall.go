package cli

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nexusrun/korta/roles"
)

func hasAWSFirewall(r roles.Role) bool {
	for _, step := range r.Steps {
		if step.Type == "firewall" {
			return true
		}
	}
	return false
}

func awsSSHSource(connection string) (netip.Addr, error) {
	fields := strings.Fields(connection)
	if len(fields) != 4 {
		return netip.Addr{}, fmt.Errorf("cannot determine the SSH source address; the server did not provide SSH_CONNECTION")
	}
	ip, err := netip.ParseAddr(fields[0])
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid SSH source address reported by the server")
	}
	return ip.Unmap(), nil
}

func validateAWSSSHRules(r roles.Role, peer netip.Addr) error {
	for _, s := range r.Steps {
		if s.Type != "firewall" || s.State != "closed" || s.Port != 22 || s.Protocol != "tcp" {
			continue
		}
		for _, source := range s.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return fmt.Errorf("invalid firewall source %q", source)
			}
			if prefix.Contains(peer) {
				return fmt.Errorf("firewall rule would close SSH access from %s; remove that rule before applying", peer)
			}
		}
	}
	return nil
}

func awsFirewallActive(ctx context.Context, run roles.Runner) (bool, error) {
	state, err := run.Run(ctx, `if systemctl is-active --quiet firewalld 2>/dev/null; then echo active; elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then echo active; else echo inactive; fi`)
	if err != nil {
		return false, fmt.Errorf("check host firewall: %w", err)
	}
	switch strings.TrimSpace(string(state)) {
	case "active":
		return true, nil
	case "inactive":
		return false, nil
	default:
		return false, fmt.Errorf("cannot determine host firewall state")
	}
}

// enableAWSFirewall initializes UFW only when no host firewall is already
// active. A transient timer disables it if a new SSH connection cannot be
// established. The timer is cancelled only after a separate SSH command works.
func enableAWSFirewall(ctx context.Context, run roles.Runner, peer netip.Addr, r roles.Role) (bool, error) {
	active, err := awsFirewallActive(ctx, run)
	if err != nil {
		return false, err
	}
	if active {
		return false, nil
	}
	id, err := randomAWSID("korta-ufw-")
	if err != nil {
		return false, err
	}
	// The role parser normalizes all sources as CIDRs and validates ports and
	// protocols. Validate again before placing any values in a shell script.
	var rules strings.Builder
	fmt.Fprintf(&rules, "ufw allow from '%s' to any port 22 proto tcp >/dev/null\n", peer.String())
	for _, s := range r.Steps {
		if s.Type != "firewall" || s.State != "open" {
			continue
		}
		if s.Port < 1 || s.Port > 65535 || (s.Protocol != "tcp" && s.Protocol != "udp") {
			return false, fmt.Errorf("invalid firewall port or protocol")
		}
		for _, source := range s.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return false, fmt.Errorf("invalid firewall source %q", source)
			}
			fmt.Fprintf(&rules, "ufw allow from '%s' to any port %d proto %s >/dev/null\n", prefix.String(), s.Port, s.Protocol)
		}
	}
	script := `set -eu
if ! command -v ufw >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || { echo 'UFW is not installed; add a supported firewall before retrying' >&2; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null
  apt-get install -y -q ufw >/dev/null
fi
command -v systemd-run >/dev/null 2>&1 || { echo 'systemd-run is required for safe firewall rollback' >&2; exit 1; }
` + rules.String() + fmt.Sprintf(`systemd-run --quiet --unit='%s' --on-active=180s /usr/sbin/ufw --force disable
ufw --force enable >/dev/null
`, id)
	if _, err := run.Run(ctx, script); err != nil {
		return false, fmt.Errorf("enable UFW: %w; if activation began, it will be rolled back automatically", err)
	}
	if _, err := run.Run(ctx, "true"); err != nil {
		return false, fmt.Errorf("SSH verification after enabling UFW failed; UFW will be disabled automatically in three minutes: %w", err)
	}
	if _, err := run.Run(ctx, fmt.Sprintf("systemctl stop '%s.timer'", id)); err != nil {
		return false, fmt.Errorf("could not cancel the UFW rollback timer; UFW will be disabled automatically: %w", err)
	}
	return true, nil
}

// finishAWSFirewall records activation and refreshes firewall results before
// the apply is printed or written to its run log.
func finishAWSFirewall(ctx context.Context, run roles.Runner, peer netip.Addr, compiled roles.Role, target roles.Target, result *roles.HostResult) error {
	changed, err := enableAWSFirewall(ctx, run, peer, compiled)
	activation := roles.StepResult{Step: len(result.Steps) + 1, Name: "Enable UFW", Status: roles.StatusOK, Detail: "firewall already active"}
	if err != nil {
		activation.Status, activation.Detail = "failed", err.Error()
		result.Steps = append(result.Steps, activation)
		return err
	}
	if changed {
		activation.Status, activation.Detail = roles.StatusChanged, "enabled UFW and verified SSH access"
		result.Status = "changed"
	}
	firewall := roles.Role{Name: compiled.Name}
	positions := []int{}
	for i, step := range compiled.Steps {
		if step.Type == "firewall" {
			firewall.Steps = append(firewall.Steps, step)
			positions = append(positions, i-1)
		}
	}
	target.Prepare = nil
	checked := roles.RunHost(ctx, firewall, target, true)
	for i, step := range checked.Steps {
		if i >= len(positions) {
			break
		}
		pos := positions[i]
		if pos >= 0 && pos < len(result.Steps) {
			step.Step = result.Steps[pos].Step
			result.Steps[pos] = step
			if step.Status == roles.StatusChanged && result.Status == "ok" {
				result.Status = "changed"
			}
		}
	}
	result.Steps = append(result.Steps, activation)
	for _, step := range checked.Steps {
		if step.Status == roles.StatusSkipped {
			return fmt.Errorf("firewall rules were skipped after activation: %s", step.Detail)
		}
	}
	if checked.Status == "failed" {
		return fmt.Errorf("firewall rule verification failed: %s", checked.Error)
	}
	return nil
}
