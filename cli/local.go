package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/nexusrun/korta/hostos"
	"github.com/nexusrun/korta/inventory"
	"github.com/nexusrun/korta/roles"
	"github.com/nexusrun/korta/sshclient"
)

// Offline mode: korta plan, apply and inventory run roles straight from this
// machine over SSH, with hosts from a Markdown inventory and no manager.

// planParallel is how many hosts a plan checks at once; plans change nothing.
const planParallel = 10

func (c *client) local(ctx context.Context) error {
	o := c.opts
	if o.set("timeout") {
		d, _ := time.ParseDuration(o.values["timeout"])
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	// Recognize provisioning before requiring an offline inventory.
	if len(o.args) == 2 && o.args[0] != "inventory" {
		if b, err := os.ReadFile(o.args[1]); err == nil {
			if gcp, _ := roles.ParseGCP(string(b)); gcp != nil {
				return fmt.Errorf("GCP provisioning requires a Korta Enterprise manager; use korta roles create, plan and apply")
			}
			if aws, _ := roles.ProvisionsAWS(string(b)); aws {
				return fmt.Errorf("AWS provisioning requires a Korta Enterprise manager; use korta roles create, plan and apply")
			}
		}
	}
	hosts, err := c.inventory()
	if err != nil {
		return err
	}
	if o.args[0] == "inventory" {
		if len(o.args) != 1 {
			return fmt.Errorf("usage: korta inventory -i hosts.md [--limit SELECTOR]")
		}
		return c.printInventory(hosts)
	}
	if len(o.args) != 2 {
		return fmt.Errorf("usage: korta %s ROLE.md -i hosts.md [--limit SELECTOR]", o.args[0])
	}
	role, err := c.loadRole(o.args[1])
	if err != nil {
		return err
	}
	sshConfig := firstOf(o.values["ssh-config"], os.Getenv("KORTA_SSH_CONFIG"))
	if sshConfig != "" {
		if _, err := os.Stat(sshConfig); err != nil {
			return fmt.Errorf("--ssh-config: %w", err)
		}
	}
	targets := make([]roles.Target, len(hosts))
	for i, h := range hosts {
		targets[i] = target(h, sshConfig)
		targets[i].Prepare = role.prepare(h)
	}
	plan := roles.Run{Kind: "plan", RoleID: role.name, Hash: role.hash()}
	fmt.Fprintf(c.errOut, "Planning %s on %s\n", role.name, count(strconv.Itoa(len(hosts)), "host"))
	for _, h := range roles.RunHosts(ctx, roles.Role{Name: role.name}, targets, false, planParallel) {
		plan.Add(roles.RedactResult(h, role.secretValues()))
	}
	plan.Risks, _ = role.review()
	if o.args[0] == "plan" {
		if err := c.printRun(plan, true); err != nil {
			return err
		}
		if plan.Failed > 0 {
			return fmt.Errorf("the plan failed on %s", count(strconv.Itoa(plan.Failed), "host"))
		}
		return nil
	}
	return c.localApply(ctx, role, targets, plan)
}

func (c *client) localApply(ctx context.Context, role *localRole, targets []roles.Target, plan roles.Run) error {
	o := c.opts
	_, commands := role.review()
	if c.format() != "json" {
		if err := c.printRun(plan, false); err != nil {
			return err
		}
	}
	switch {
	case plan.Failed > 0:
		return fmt.Errorf("the plan failed on %s; nothing was applied", count(strconv.Itoa(plan.Failed), "host"))
	case plan.Changes == 0:
		if c.format() != "json" {
			fmt.Fprintln(c.out, "Nothing to change: the hosts already match the role.")
		}
		return nil
	case commands && !o.yes("confirm-commands"):
		return fmt.Errorf("this role runs custom scripts or check commands as root; review them, then add --confirm-commands")
	}
	for _, r := range plan.Risks {
		fmt.Fprintf(c.errOut, "review: %s\n", clean(r))
	}
	// Apply exactly where the plan found changes.
	changed := []roles.Target{}
	for i, h := range plan.Hosts {
		if h.Changed() > 0 {
			changed = append(changed, targets[i])
		}
	}
	question := fmt.Sprintf("Apply %s to %s?", count(strconv.Itoa(plan.Changes), "change"), count(strconv.Itoa(len(changed)), "host"))
	if err := c.confirm(question); err != nil {
		return err
	}
	batch := max(role.rollout.BatchSize, 1)
	run := roles.Run{Kind: "apply", RoleID: role.name, Hash: role.hash(), Risks: plan.Risks}
	for start := 0; start < len(changed); start += batch {
		group := changed[start:min(start+batch, len(changed))]
		if run.Failed > 0 && !role.rollout.ContinueOnFailure {
			for _, t := range group {
				run.Add(roles.HostResult{Instance: t.Name, Status: "skipped", Error: "not run: an earlier batch failed"})
			}
			continue
		}
		for _, h := range roles.RunHosts(ctx, roles.Role{Name: role.name}, group, true, batch) {
			h = roles.RedactResult(h, role.secretValues())
			fmt.Fprintf(c.errOut, "  %-8s %s\n", h.Status, h.Instance)
			run.Add(h)
		}
	}
	if path, err := c.saveRunLog(role, plan, run); err == nil {
		fmt.Fprintf(c.errOut, "Run log: %s\n", path)
	} else {
		fmt.Fprintf(c.errOut, "Could not write the run log: %v\n", err)
	}
	if err := c.printRun(run, false); err != nil {
		return err
	}
	if run.Failed > 0 {
		return fmt.Errorf("the role failed on %s", count(strconv.Itoa(run.Failed), "host"))
	}
	return nil
}

// confirm asks on the terminal unless --yes was given.
func (c *client) confirm(question string) error {
	if c.opts.yes("yes") {
		return nil
	}
	f, ok := c.in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return fmt.Errorf("%s Not applied: add --yes to apply without a prompt", question)
	}
	fmt.Fprintf(c.errOut, "%s [y/N] ", question)
	answer, _ := bufio.NewReader(f).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return fmt.Errorf("not applied")
	}
	return nil
}

// printRun prints a plan or apply as JSON or as the role run table.
func (c *client) printRun(run roles.Run, hint bool) error {
	b, err := json.Marshal(run)
	if err != nil {
		return err
	}
	if c.format() == "json" {
		return c.print(b)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err = d.Decode(&m); err != nil {
		return err
	}
	if hint {
		cmd := []string{"korta", "apply", c.opts.args[1]}
		for _, f := range []string{"inventory", "limit", "name", "ssh-config"} {
			if v := c.opts.values[f]; v != "" {
				cmd = append(cmd, "--"+f, quote(v))
			}
		}
		m["applyHint"] = "Review it, then apply it with: " + strings.Join(cmd, " ")
	} else if run.Kind == "plan" {
		m["kind"] = "apply-preview"
	}
	c.roleRun(m)
	return nil
}

func quote(s string) string {
	if strings.ContainsAny(s, " '\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func (c *client) inventory() ([]inventory.Host, error) {
	path := firstOf(c.opts.values["inventory"], os.Getenv("KORTA_INVENTORY"))
	if path == "" {
		if _, err := os.Stat("inventory.md"); err != nil {
			return nil, fmt.Errorf("choose hosts with -i hosts.md (or KORTA_INVENTORY, or an inventory.md in this directory)")
		}
		path = "inventory.md"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hosts, err := inventory.Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if hosts, err = inventory.Select(hosts, c.opts.values["limit"]); err != nil {
		return nil, err
	}
	// --identity wins over the inventory; its relative paths are from here.
	override := firstOf(c.opts.values["identity"], os.Getenv("KORTA_IDENTITY"))
	if override != "" {
		key, err := resolveIdentity(override, ".")
		if err != nil {
			return nil, fmt.Errorf("--identity: %w", err)
		}
		for i := range hosts {
			hosts[i].Identity = key
		}
		return hosts, nil
	}
	for i, h := range hosts {
		if h.Identity == "" {
			continue
		}
		if hosts[i].Identity, err = resolveIdentity(h.Identity, filepath.Dir(path)); err != nil {
			return nil, fmt.Errorf("%s: line %d: host %s: %w", path, h.Line, h.Name, err)
		}
	}
	return hosts, nil
}

// resolveIdentity expands ${VAR} and ~ on the machine running korta, so one
// inventory works from laptops and CI. Other relative paths are from dir.
func resolveIdentity(path, dir string) (string, error) {
	var missing []string
	path = os.Expand(path, func(name string) string {
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("the identity uses $%s, which is not set", missing[0])
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(path)
	switch {
	case err != nil:
		return "", fmt.Errorf("private key %s: %w", path, errors.Unwrap(err))
	case !st.Mode().IsRegular():
		return "", fmt.Errorf("private key %s is not a file", path)
	}
	return path, nil
}

func (c *client) printInventory(hosts []inventory.Host) error {
	if c.format() == "json" {
		b, _ := json.Marshal(hosts)
		return c.print(b)
	}
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRESS\tGROUPS\tIDENTITY\tLABELS")
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	for _, h := range hosts {
		labels := map[string]any{}
		for k, v := range h.Labels {
			labels[k] = v
		}
		key := h.Identity
		if rel, err := filepath.Rel(cwd, key); err == nil && key != "" && !strings.HasPrefix(rel, "..") {
			key = rel
		} else if home != "" && strings.HasPrefix(key, home+string(filepath.Separator)) {
			key = "~" + strings.TrimPrefix(key, home)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", h.Name, address(h), firstOf(strings.Join(h.Groups, " / "), "-"), firstOf(key, "ssh default"), firstOf(pairs(labels), "-"))
	}
	return w.Flush()
}

func address(h inventory.Host) string {
	a := h.Address
	if strings.Contains(a, ":") {
		a = "[" + a + "]"
	}
	if h.User != "" {
		a = h.User + "@" + a
	}
	if h.Port != 0 {
		a += ":" + strconv.Itoa(h.Port)
	}
	return a
}

// target connects with the user's SSH setup and detects the OS, which
// decides how steps run.
func target(h inventory.Host, sshConfig string) roles.Target {
	return roles.Target{ID: h.Name, Name: h.Name, Connect: func(ctx context.Context) (roles.Runner, roles.Host, error) {
		run := sshRunner{sshclient.System{Host: h.Address, Port: h.Port, User: h.User, ConfigFile: sshConfig, IdentityFile: h.Identity}}
		out, err := run.Run(ctx, hostos.Script)
		if err != nil {
			return nil, roles.Host{}, err
		}
		p, err := hostos.Parse(out)
		if err != nil {
			return nil, roles.Host{}, err
		}
		return run, roles.Host{Family: p.Family, Distro: p.Distro, Version: p.Version, Arch: p.Arch}, nil
	}}
}

// sshRunner runs scripts as root: directly when logged in as root, else
// through sudo without a password prompt.
type sshRunner struct{ ssh sshclient.System }

const asRoot = `if [ "$(id -u)" -eq 0 ]; then exec sh -s 2>&1; else exec sudo -n sh -s 2>&1; fi`

func (r sshRunner) Run(ctx context.Context, script string) ([]byte, error) {
	out, err := r.ssh.Run(ctx, asRoot, strings.NewReader(script))
	if err != nil {
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		if tail := strings.TrimSpace(strings.Join(lines, "\n")); tail != "" {
			err = fmt.Errorf("%w\n%s", err, tail)
		}
	}
	return out, err
}

// saveRunLog keeps a local record of each apply, standing in for the
// manager's audit log.
func (c *client) saveRunLog(role *localRole, plan, run roles.Run) (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	dir = filepath.Join(dir, "korta", "runs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	user := firstOf(os.Getenv("USER"), os.Getenv("USERNAME"))
	b, _ := json.MarshalIndent(map[string]any{
		"time": time.Now().UTC(), "user": user, "role": role.name, "hash": role.hash(),
		"markdown": role.markdown, "limit": c.opts.values["limit"], "plan": plan, "apply": run,
	}, "", "  ")
	path := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+"-"+role.name+".json")
	return path, os.WriteFile(path, append(b, '\n'), 0600)
}
