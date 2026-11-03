package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/nexusrun/korta/hostos"
	"github.com/nexusrun/korta/internal/awsprovider"
	"github.com/nexusrun/korta/inventory"
	"github.com/nexusrun/korta/roles"
	"github.com/nexusrun/korta/sshclient"
	"golang.org/x/crypto/ssh"
)

type awsPreview struct {
	Kind   string             `json:"kind"`
	Cloud  cloud.Plan         `json:"cloud"`
	Hosts  []roles.HostResult `json:"hosts"`
	Risks  []string           `json:"risks,omitempty"`
	Notice string             `json:"notice"`
}

func (c *client) localAWS(ctx context.Context, path string) error {
	for _, flag := range []string{"inventory", "limit", "identity", "ssh-config"} {
		if c.opts.set(flag) {
			return fmt.Errorf("--%s is not supported for standalone AWS roles", flag)
		}
	}
	if c.opts.args[0] == "apply" && c.format() == "json" {
		return fmt.Errorf("standalone AWS apply does not yet support JSON output; use table output")
	}
	role, err := c.loadRoleMode(path, true)
	if err != nil {
		return err
	}
	compiled, err := role.compile(roles.SampleFacts())
	if err != nil {
		return err
	}
	a := compiled.AWS()
	if a == nil {
		return fmt.Errorf("standalone AWS network roles are not supported; choose an existing VPC and subnet")
	}
	if a.Network != "" || a.StaticIP || a.KeyPair != "" || a.SSHKey != "" || a.LoadBalancer != nil || len(a.DNS) != 0 {
		return fmt.Errorf("standalone AWS roles do not yet support network presets, static IPs, custom key pairs, load balancers or DNS")
	}
	dir, err := awsStateDir(path)
	if err != nil {
		return err
	}
	state, err := readAWSState(dir)
	if err != nil {
		return err
	}
	if state.Version != 0 && state.OwnerName != role.name {
		return fmt.Errorf("role name changed; restore the original --name before retrying")
	}
	if err := checkAWSSpec(state, *a); err != nil {
		return err
	}
	provider := c.aws
	if provider == nil {
		provider = cloud.AWS{}
	}
	cred := cloud.Credentials{Method: "environment"}
	request := cloud.Request{Spec: *a, Account: state.Account}
	// Keep the chosen image fixed for additional instances after the first launch.
	for _, reservation := range state.Reservations {
		if reservation.Spec.Image != "" {
			request.Spec.Image = reservation.Spec.Image
			break
		}
	}
	for _, step := range compiled.Steps {
		if step.Type == "firewall" && step.State == "open" {
			request.Ingress = append(request.Ingress, cloud.Rule{Protocol: step.Protocol, Port: step.Port, CIDRs: step.Sources})
		}
	}
	requestJSON, _ := json.Marshal(request)
	for _, secret := range role.secretValues() {
		if secret != "" && strings.Contains(string(requestJSON), secret) {
			return fmt.Errorf("secret values cannot be used in AWS provisioning settings")
		}
	}
	plan, err := provider.Resolve(ctx, cred, request)
	if err != nil {
		return role.redact(err)
	}
	if len(plan.Subnets) == 0 {
		return fmt.Errorf("AWS returned no usable subnets")
	}
	preview := awsPreview{Kind: "plan", Cloud: plan, Notice: "AWS resources may incur charges. New hosts cannot be inspected until after launch. Their SSH host keys are trusted on first use and pinned. When firewall rules are present, Korta will enable UFW if no host firewall is active."}
	preview.Risks = compiled.Risky()
	for i := range preview.Risks {
		preview.Risks[i] = roles.Redact(preview.Risks[i], role.secretValues())
	}
	for _, name := range a.InstanceNames() {
		h := roles.HostResult{InstanceID: name, Instance: name, Status: "changed"}
		if res, ok := state.Reservations[name]; ok && res.InstanceID != "" {
			h.Status = "ok"
		}
		h.Steps = append(h.Steps, roles.StepResult{Step: 1, Name: "EC2 instance", Status: h.Status})
		for i, step := range compiled.Steps[1:] {
			h.Steps = append(h.Steps, roles.StepResult{Step: i + 2, Name: roles.StepName(step), Status: "not run", Detail: "Host configuration is checked after the instance is reachable"})
		}
		preview.Hosts = append(preview.Hosts, h)
	}
	b, _ := json.Marshal(preview)
	if c.format() == "json" {
		if err := c.print(b); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(c.out, "AWS account: %s\nRegion: %s\nImage: %s\nInstance type: %s\nVPC: %s\nSubnets: %s\n", plan.Account, plan.Spec.Region, plan.Spec.Image, plan.Spec.InstanceType, plan.VPC, strings.Join(plan.Subnets, ", "))
		for _, h := range preview.Hosts {
			fmt.Fprintf(c.out, "  %s: %s\n", h.Instance, h.Status)
		}
		for _, rule := range plan.Ingress {
			fmt.Fprintf(c.out, "  ingress %s/%d from %s\n", rule.Protocol, rule.Port, strings.Join(rule.CIDRs, ", "))
		}
		fmt.Fprintln(c.out, preview.Notice)
	}
	if c.opts.args[0] == "plan" {
		return nil
	}
	if compiled.HasCommand() && !c.opts.yes("confirm-commands") {
		return fmt.Errorf("this role runs custom scripts or check commands as root; review them, then add --confirm-commands")
	}
	if err := c.confirm("Provision and configure these AWS instances?"); err != nil {
		return err
	}
	unlock, err := lockAWSState(dir)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := readAWSState(dir)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(state, current) {
		return fmt.Errorf("AWS role state changed since the plan; run the command again")
	}
	again, err := provider.Resolve(ctx, cred, request)
	if err != nil {
		return role.redact(err)
	}
	if !reflect.DeepEqual(plan, again) {
		return fmt.Errorf("AWS settings changed since the plan; run the command again")
	}
	if state.Version == 0 {
		owner, err := randomAWSID("role_")
		if err != nil {
			return err
		}
		state = awsLocalState{Version: 1, OwnerID: owner, OwnerName: role.name, Account: plan.Account, Spec: *a, Reservations: map[string]awsReservation{}}
		if err = writeAWSState(dir, state); err != nil {
			return err
		}
	}
	state.Spec.Count = a.Count
	if err := writeAWSState(dir, state); err != nil {
		return err
	}
	private, public, err := awsLocalKey(dir, state)
	if err != nil {
		return err
	}
	owner := cloud.Owner{ID: state.OwnerID, Name: role.name}
	fleet, prepErr := provider.Prepare(ctx, cred, plan, owner, public, state.Fleet)
	state.Fleet = fleet
	if err := writeAWSState(dir, state); err != nil {
		return err
	}
	if prepErr != nil {
		return role.redact(prepErr)
	}
	for i, name := range a.InstanceNames() {
		res, exists := state.Reservations[name]
		if !exists {
			token, err := randomAWSID("korta-")
			if err != nil {
				return err
			}
			spec := plan.Spec
			spec.Name = name
			spec.Count = 1
			spec.Subnet = plan.Subnets[i%len(plan.Subnets)]
			spec.KeyPair = fleet.KeyPair
			spec.SecurityGroups = append([]string{}, plan.Spec.SecurityGroups...)
			if fleet.SecurityGroup != "" {
				spec.SecurityGroups = append(spec.SecurityGroups, fleet.SecurityGroup)
			}
			spec.SecurityGroups = append(spec.SecurityGroups, plan.ExtraGroups...)
			res = awsReservation{Token: token, Spec: spec}
			state.Reservations[name] = res
			if err := writeAWSState(dir, state); err != nil {
				return err
			}
		}
		if res.InstanceID == "" {
			res.InstanceID, err = provider.Launch(ctx, cred, res.Spec, res.Token, state.Account)
			if err != nil {
				return role.redact(err)
			}
			state.Reservations[name] = res
			if err := writeAWSState(dir, state); err != nil {
				return err
			}
		}
		address, err := provider.Address(ctx, cred, res.Spec, res.InstanceID, state.Account)
		if err != nil {
			return role.redact(err)
		}
		if res.Host != "" && res.Host != address && res.HostKey != "" {
			return fmt.Errorf("address for %s changed from %s to %s; inspect the instance and its SSH host key before retrying", name, res.Host, address)
		}
		res.Host = address
		state.Reservations[name] = res
		if err := writeAWSState(dir, state); err != nil {
			return err
		}
		if res.HostKey == "" {
			scan := c.awsScan
			if scan == nil {
				scan = awsWaitHostKey
			}
			res.HostKey, err = scan(ctx, address)
			if err != nil {
				return err
			}
			fp, err := sshclient.HostFingerprint(res.HostKey)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.errOut, "Trusting first SSH host key for %s (%s): %s\n", name, address, fp)
			state.Reservations[name] = res
			if err := writeAWSState(dir, state); err != nil {
				return err
			}
		}
		configure := c.awsConfigure
		if configure == nil {
			configure = c.applyAWSHost
		}
		if err := configure(ctx, role, res, name, private, dir); err != nil {
			return err
		}
	}
	return nil
}

func checkAWSSpec(state awsLocalState, spec roles.AWSInstance) error {
	if state.Version == 0 {
		return nil
	}
	if state.OwnerID == "" || state.Account == "" || state.Reservations == nil {
		return fmt.Errorf("AWS state is incomplete; inspect it before retrying")
	}
	old := state.Spec
	compare := spec
	old.Count = 0
	compare.Count = 0
	if !reflect.DeepEqual(old, compare) {
		return fmt.Errorf("AWS launch settings changed; restore them before retrying")
	}
	if spec.Count < state.Spec.Count || spec.Count < len(state.Reservations) {
		return fmt.Errorf("AWS instance count can only grow; restore the previous count")
	}
	desired := map[string]bool{}
	for _, name := range spec.InstanceNames() {
		desired[name] = true
	}
	for name, res := range state.Reservations {
		if res.Token == "" || res.Spec.Name != name || res.Spec.Image == "" || res.Spec.Subnet == "" {
			return fmt.Errorf("AWS reservation %s is incomplete; inspect state before retrying", name)
		}
		if !desired[name] {
			return fmt.Errorf("AWS state contains unexpected reservation %s; inspect it before retrying", name)
		}
	}
	return nil
}

func awsLocalKey(dir string, state awsLocalState) (string, string, error) {
	path := filepath.Join(dir, "identity")
	info, statErr := os.Lstat(path)
	if statErr == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return "", "", fmt.Errorf("AWS identity must be a private regular file: %s", path)
	}
	if statErr != nil && !os.IsNotExist(statErr) {
		return "", "", statErr
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if state.Fleet.KeyPair != "" || len(state.Reservations) != 0 {
			return "", "", fmt.Errorf("the AWS role's private key is missing; recover it from backup before retrying")
		}
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", "", e
		}
		block, e := ssh.MarshalPrivateKey(key, "korta")
		if e != nil {
			return "", "", e
		}
		b = pem.EncodeToMemory(block)
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", "", e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return "", "", e
		}
		if closeErr != nil {
			return "", "", closeErr
		}
	} else if err != nil {
		return "", "", err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return "", "", fmt.Errorf("AWS identity must be a private regular file: %s", path)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", "", fmt.Errorf("cannot read AWS identity: %s", path)
	}
	return string(b), string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

func awsWaitHostKey(ctx context.Context, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		key, err := sshclient.ScanHostKey(ctx, host, 22)
		if err == nil {
			return key, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("SSH host key not available for %s; retry the role", host)
		case <-time.After(5 * time.Second):
		}
	}
}

type awsSSHRunner struct{ session *sshclient.Session }

func (r awsSSHRunner) Run(ctx context.Context, script string) ([]byte, error) {
	return r.session.Run(ctx, asRoot, strings.NewReader(script))
}
func (c *client) applyAWSHost(ctx context.Context, role *localRole, res awsReservation, name, private, dir string) error {
	session, err := sshclient.New(sshclient.Config{Host: res.Host, User: res.Spec.User, Port: 22, SecretID: "local", HostKey: res.HostKey}, sshclient.Identity{PrivateKey: private}, dir)
	if err != nil {
		return err
	}
	defer session.Close()
	run := awsSSHRunner{session}
	host := inventory.Host{Name: name, Address: res.Host}
	t := roles.Target{ID: res.InstanceID, Name: name, Connect: func(ctx context.Context) (roles.Runner, roles.Host, error) {
		out, err := run.Run(ctx, hostos.Script)
		if err != nil {
			return nil, roles.Host{}, err
		}
		p, err := hostos.Parse(out)
		if err != nil {
			return nil, roles.Host{}, err
		}
		return run, roles.Host{Family: p.Family, Distro: p.Distro, Version: p.Version, Arch: p.Arch}, nil
	}, Prepare: func(h roles.Host) (roles.Role, error) {
		r, err := role.prepare(host)(h)
		if err == nil && r.AWS() != nil {
			r.Steps = r.Steps[1:]
		}
		return r, err
	}}
	result := roles.RedactResult(roles.RunHost(ctx, roles.Role{Name: role.name}, t, false), role.secretValues())
	role.mu.Lock()
	compiled := role.compiled[name]
	role.mu.Unlock()
	if !hasAWSFirewall(compiled) {
		plan := roles.Run{Kind: "plan", RoleID: role.name, Hash: role.hash()}
		plan.Add(result)
		plan.Risks, _ = role.review()
		return c.localApply(ctx, role, []roles.Target{t}, plan)
	}
	peerOut, err := session.Run(ctx, `printf '%s\n' "$SSH_CONNECTION"`, nil)
	if err != nil {
		return fmt.Errorf("cannot determine the SSH source address: %w", err)
	}
	peer, err := awsSSHSource(string(peerOut))
	if err != nil {
		return err
	}
	if err := validateAWSSSHRules(compiled, peer); err != nil {
		return err
	}
	active, err := awsFirewallActive(ctx, run)
	if err != nil {
		return err
	}
	if !active {
		result.Steps = append(result.Steps, roles.StepResult{Step: len(result.Steps) + 1, Name: "Enable UFW", Status: roles.StatusChanged, Detail: "Allow SSH from " + peer.String() + " and the role's open ports; automatic rollback if SSH fails"})
	}
	plan := roles.Run{Kind: "plan", RoleID: role.name, Hash: role.hash()}
	plan.Add(result)
	plan.Risks, _ = role.review()
	if active {
		return c.localApply(ctx, role, []roles.Target{t}, plan)
	}
	return c.localApplyFinalized(ctx, role, []roles.Target{t}, plan, func(result *roles.HostResult) error {
		return finishAWSFirewall(ctx, run, peer, compiled, t, result)
	})
}
