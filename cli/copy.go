package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/nexusrun/korta/inventory"
	"github.com/nexusrun/korta/sshclient"
)

var copyAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var copyMode = regexp.MustCompile(`^0?[0-7]{3,4}$`)
var copyPath = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]{1,250}$`)
var copyObservedMode = regexp.MustCompile(`^[0-7]{1,4}$`)
var copyHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type copyResult struct {
	Host   string `json:"host"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type copyTarget struct {
	host    inventory.Host
	state   string
	changed bool
}

func copySSH(h inventory.Host, config string) sshclient.System {
	return sshclient.System{Host: h.Address, Port: h.Port, User: h.User, IdentityFile: h.Identity, ConfigFile: config}
}
func copyRootCommand(script string) string {
	return `if [ "$(id -u)" -eq 0 ]; then exec sh -c ` + quote(script) + `; else exec sudo -n sh -c ` + quote(script) + `; fi`
}

const copyObserve = `observe() {
 if [ -L "$dest" ]; then echo 'destination is a symbolic link'; return 1; fi
 if [ ! -e "$dest" ]; then printf 'missing\n'; return; fi
 if [ ! -f "$dest" ]; then echo 'destination is not a regular file'; return 1; fi
 hash=$(sha256sum -- "$dest"); hash=${hash%% *}
 printf 'file %s %s\n' "$hash" "$(stat -c '%a %U %G' -- "$dest")"
}
`

func observeCopy(ctx context.Context, ssh sshclient.System, path string) (string, error) {
	script := "set -eu\ndest=" + quote(path) + "\n" + copyObserve + "observe\n"
	out, err := ssh.Run(ctx, copyRootCommand(script), nil)
	if err != nil {
		return "", fmt.Errorf("could not inspect destination: %w", err)
	}
	line := strings.TrimSpace(string(out))
	fields := strings.Fields(line)
	if line == "missing" {
		return line, nil
	}
	if len(fields) != 5 || fields[0] != "file" || !copyHash.MatchString(fields[1]) || !copyObservedMode.MatchString(fields[2]) || !copyAccount.MatchString(fields[3]) || !copyAccount.MatchString(fields[4]) {
		return "", fmt.Errorf("could not interpret destination metadata; check the remote path and required tools")
	}
	return line, nil
}

func (c *client) copyFile(ctx context.Context) error {
	o := c.opts
	if len(o.args) != 3 {
		return fmt.Errorf("usage: korta copy SOURCE DESTINATION -i hosts.md [--limit SELECTOR] [--dry-run]")
	}
	src, dest := o.args[1], o.args[2]
	if path.Clean(dest) != dest || !copyPath.MatchString(dest) || strings.Contains(dest, "/../") || strings.HasSuffix(dest, "/..") || strings.Contains(dest, "//") || strings.HasSuffix(dest, "/") {
		return fmt.Errorf("destination must be an absolute file path without .. or repeated slashes")
	}
	for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/boot"} {
		if dest == p || strings.HasPrefix(dest, p+"/") {
			return fmt.Errorf("destination is under a protected system path")
		}
	}
	owner := firstOf(o.values["owner"], "root")
	group := firstOf(o.values["group"], owner)
	mode := firstOf(o.values["mode"], "0644")
	if !copyAccount.MatchString(owner) || !copyAccount.MatchString(group) || !copyMode.MatchString(mode) {
		return fmt.Errorf("owner and group must be account names; mode must be octal, such as 0644")
	}
	mode = strings.TrimLeft(mode, "0")
	if mode == "" {
		mode = "0"
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
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file, not a directory or symlink")
	}
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return fmt.Errorf("read source: %w", err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
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
	targets := make([]copyTarget, 0, len(hosts))
	results := make([]copyResult, 0, len(hosts))
	failed, changed := 0, 0
	for _, h := range hosts {
		state, err := observeCopy(ctx, copySSH(h, config), dest)
		if err != nil {
			failed++
			results = append(results, copyResult{h.Name, "failed", err.Error()})
			continue
		}
		wanted := "file " + digest + " " + mode + " " + owner + " " + group
		different := state != wanted
		targets = append(targets, copyTarget{h, state, different})
		status := "unchanged"
		if different {
			status = "would change"
			changed++
		}
		results = append(results, copyResult{h.Name, status, dest})
	}
	if c.format() != "json" || o.yes("dry-run") || changed == 0 || failed > 0 {
		if err := c.printCopy(results); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("copy inspection failed on %s; nothing was copied", count(fmt.Sprint(failed), "host"))
	}
	if o.yes("dry-run") || changed == 0 {
		return nil
	}
	if err := c.confirm(fmt.Sprintf("Copy %s to %s on %s?", src, dest, count(fmt.Sprint(changed), "host"))); err != nil {
		return err
	}
	results = nil
	failed = 0
	for _, t := range targets {
		if !t.changed {
			results = append(results, copyResult{t.host.Name, "unchanged", dest})
			continue
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind source: %w", err)
		}
		script := `set -eu
 dest=` + quote(dest) + `\n` + copyObserve + `expected=` + quote(t.state) + `
 current=$(observe)
 [ "$current" = "$expected" ] || { echo 'destination changed after inspection; inspect again'; exit 1; }
 dir=${dest%/*}; [ -n "$dir" ] || dir=/
 [ -d "$dir" ] || { echo 'destination directory does not exist'; exit 1; }
 tmp=$(mktemp "$dir/.korta-copy.XXXXXXXX")
 trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
 cat > "$tmp"
 sum=$(sha256sum -- "$tmp"); sum=${sum%% *}
 [ "$sum" = ` + quote(digest) + ` ] || { echo 'source changed during copying; inspect again'; exit 1; }
 chown ` + quote(owner+":"+group) + ` "$tmp"
 chmod ` + quote(mode) + ` "$tmp"
 current=$(observe)
 [ "$current" = "$expected" ] || { echo 'destination changed during copying; inspect again'; exit 1; }
 mv -f -- "$tmp" "$dest"
 if command -v restorecon >/dev/null 2>&1; then restorecon -F "$dest"; fi
 `
		// A literal newline separates the assignment from the shell function.
		script = strings.Replace(script, `\n`, "\n", 1)
		out, err := copySSH(t.host, config).Run(ctx, copyRootCommand(script), file)
		if err != nil {
			failed++
			detail := "copy failed"
			if text := strings.TrimSpace(string(out)); text != "" {
				detail = text
			}
			results = append(results, copyResult{t.host.Name, "failed", detail})
			continue
		}
		results = append(results, copyResult{t.host.Name, "copied", dest})
	}
	if err := c.printCopy(results); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("copy failed on %s", count(fmt.Sprint(failed), "host"))
	}
	return nil
}

func (c *client) printCopy(rows []copyResult) error {
	if c.format() == "json" {
		b, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		return c.print(b)
	}
	for _, r := range rows {
		fmt.Fprintf(c.out, "%-20s %-13s %s\n", r.Host, r.Status, r.Detail)
	}
	return nil
}
