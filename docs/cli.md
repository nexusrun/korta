# Korta CLI

`korta` runs Markdown roles on your hosts over SSH (offline mode, below). With
Korta Enterprise it also manages the same platform as the web console: instances, SSH keys,
databases, applications, roles, operations and an interactive SSH console. Every
command goes through the manager, and SSH private keys stay in its vault.

Help follows the command path. Use `korta --help` for the overview,
`korta instances --help` for instance commands, and
`korta instances create --help` for creation options and examples. The same
scoping works for every command group and action; `-h` is an alias for `--help`.
A bare group such as `korta roles` also displays that group's help. Help does
not connect to a manager or read configuration, inventory, or request files.

## Offline mode

Run roles straight from your machine, without a manager. Hosts come from a
Markdown inventory and SSH uses your own setup: `~/.ssh/config`, ssh-agent and
`~/.ssh/known_hosts`.

```markdown
Production fleet.

# Databases
- db1 ubuntu@10.0.0.5 env=prod
- db2 ubuntu@10.0.0.6:2222 env=prod
  - role=replica

# Web
- web1 deploy@web1.internal env=staging
- web2.internal
```

Each heading is a group; deeper headings are subgroups. Each bullet is a host:
a name, then `[user@]host[:port]`, then `KEY=VALUE` labels. A nested bullet adds
labels to the host above it. A bullet with only an address, or an alias from
`~/.ssh/config`, uses it as the name. Write IPv6 addresses in brackets, such as
`root@[fd00::5]:22`. Other text is notes, and mistakes are reported with their
line number.

```sh
korta inventory -i hosts.md --limit Databases
korta plan  role.md -i hosts.md --limit env=prod
korta apply role.md -i hosts.md --limit env=prod
```

`plan` changes nothing and shows every step on every host. `apply` plans first,
shows the plan, asks `Apply 6 changes to 2 hosts? [y/N]`, and then applies only
to the hosts with changes, one at a time by default (`--batch-size N`). It stops
after a failed batch unless you pass `--continue-on-failure`. In scripts and CI,
`--yes` skips the prompt; without a terminal, apply refuses unless `--yes` is
given. Roles with custom scripts also need `--confirm-commands`.

`--limit` selects hosts by group heading, host name or `KEY=VALUE` label.
Repeat it or separate selectors with commas to select more hosts. A selector
that matches nothing is an error. Without `-i`, korta uses `KORTA_INVENTORY`,
then `inventory.md` in the current directory.

### Variables

Host labels are also the variables a role uses as `{{ name }}`. A `vars:` line
sets them for a group and its subgroups, and a host's own `KEY=VALUE` wins.
Quote values with spaces or commas:

```markdown
# Shop
vars: domain=shop.example.com app_port=3000 title="Acme Shop"
- web1 deploy@10.0.0.5
- web2 deploy@10.0.0.6 app_port=4000

# Blog
vars: domain=blog.example.com db_password=${BLOG_DB_PASSWORD}
- web3 deploy@10.0.1.5
```

`--var name=value` wins over everything for one run, for example
`korta apply site.md -i hosts.md --limit web1 --var domain=staging.example.com`.
`${NAME}` reads a secret from the environment of the machine running korta. See
[Roles in Markdown](roles.md#variables-and-templates) for how roles use them.

### SSH keys

Korta never stores or asks for private keys in offline mode. It points SSH at a
key file, in this order:

1. `--identity FILE` (`-k`, or `KORTA_IDENTITY`) for every selected host.
2. `identity=FILE` on a host bullet.
3. An `identity:` line under a heading, for every host in that group and its
   subgroups. Before the first heading, it applies to the whole file.
4. Otherwise, your usual SSH setup: ssh-agent, `IdentityFile` in
   `~/.ssh/config`, and the default `~/.ssh/id_*` keys.

A `user:` line sets the SSH user for a group the same way; `user@` on a host wins.

```markdown
# Production
identity: ~/.ssh/prod_ed25519
user: ubuntu
- db1 10.0.0.5
- db2 10.0.0.6 identity=~/.ssh/db2_ed25519

# Staging
identity: ${STAGING_SSH_KEY}
user: deploy
- web1 10.1.0.5
```

Paths are resolved on the machine that runs korta, so one inventory works from
every laptop and from CI: `~` is that user's home, `${VAR}` comes from the
environment (an unset variable is an error), and other relative paths are from
the inventory file's folder. Every key file is checked before anything connects.
With a key named, SSH offers only that key.

Keys with a passphrase must be loaded with `ssh-add` first: SSH runs in batch
mode and never prompts. A loaded key is still used when it is also named with
`identity`. Key files need mode 600.

In CI, keep the key in a secret and point a variable at it:

```sh
install -m 600 /dev/null "$RUNNER_TEMP/prod_key"
printf '%s\n' "$PROD_SSH_KEY" > "$RUNNER_TEMP/prod_key"
korta apply role.md -i hosts.md --identity "$RUNNER_TEMP/prod_key" --yes
```

SSH refuses hosts that are missing from `known_hosts` or whose key changed. Connect
once with `ssh` to check and record a host's key, or commit a `known_hosts` file
and select it with `--ssh-config`. Logged in as root, steps run directly;
otherwise they run through `sudo -n`, which needs passwordless sudo.
`--ssh-config FILE` (or `KORTA_SSH_CONFIG`) replaces `~/.ssh/config`.

Each apply writes a run log with the role, plan and results to
`~/.local/state/korta/runs/` (or `$XDG_STATE_HOME/korta/runs/`). The role's
name, which names files such as its sysctl settings, comes from the file name;
`--name` overrides it. The same role file works with a manager: save it with
`korta roles create` and plan and approve it there. Deployments, the web console
and the AI assistant need a manager.

## Sign in

```sh
make build
./bin/korta login --server http://127.0.0.1:8080 --token-file data/admin-token
./bin/korta instances list
```

Install only the client with `go install ./cmd/korta`. Without `--token-file`,
`korta login` asks for the token without echoing it (or reads one line from a
pipe). It checks the token, then saves it in `korta/config.json` in your user
configuration directory with mode 0600. `korta logout` removes the saved token;
it does not rotate the manager's admin token.

| Setting  | Flag           | Environment    | Default                          |
| -------- | -------------- | -------------- | -------------------------------- |
| Manager  | `--server`     | `KORTA_SERVER` | saved server, else `http://127.0.0.1:8080` |
| Token    | `--token-file` | `KORTA_TOKEN`  | saved token                      |
| Config   | `--config`     | `KORTA_CONFIG` | user config dir `/korta/config.json` |
| Deadline | `--timeout`    |                | `10m`                            |

Flags win over the environment, which wins over saved credentials. A saved token
is only sent to the manager it was saved for. The CLI refuses to send the token
over plain HTTP to another machine: use an `https://` URL (a TLS proxy in front
of `korta-server`), or pass `--insecure` on a network you trust. Loopback
addresses are always allowed.

## Output and exit status

Lists print tables, operations print their steps and results, and other objects
print as indented JSON. Use `--json` (or `--output json`) in scripts. Errors go
to stderr and exit with status 1.

`--wait` follows an operation until it finishes, printing each step on stderr,
and exits 1 if it fails. `deployments status`, `logs` and `backups`, and `roles
plan`, wait by default; add `--wait=false` to return the operation at once.
`--timeout` limits the whole command including waiting. When it runs out, the
operation keeps running on the manager; follow it with `korta operations wait
op_ID`. Consoles are not limited by `--timeout`.

## Instances and SSH keys

```sh
korta keys create production --private-key ~/.ssh/id_ed25519
korta keys list
korta instances create db1 --host 10.0.0.5 --user ubuntu --key key_ID --label env=prod --wait
korta instances list
korta instances check ins_ID --wait
korta instances console ins_ID
korta audit --target ins_ID
```

`instances create` also takes `--port` and `--host-key 'ssh-ed25519 ...'` to pin
the host key up front, or the full JSON request with `--file`. Change an
instance with `korta instances update ins_ID --file instance.json`. After a known
reinstall, `korta instances trust-host-key ins_ID --wait` pins the new host key.
For a passphrase-protected key, pass `{"name", "privateKey", "passphrase"}` with
`keys create --file FILE`.

The console uses the manager's pinned host key and follows terminal resizes. Exit
the remote shell to close it. The manager closes idle sessions after 30 minutes
and every session after 8 hours.

## Databases and applications

```sh
korta types
korta deployments create orders-db --type postgres --instance ins_ID --file spec.json --wait
korta deployments list
korta deployments update dep_ID --file spec.json
korta deployments apply dep_ID --wait
korta deployments status dep_ID
korta deployments logs dep_ID --data '{"lines":100}'
korta deployments connection dep_ID --role orders --database orders
```

With a name and flags, `--file` holds only the spec, for example:

```json
{
  "roles": [{"name": "orders"}],
  "databases": [{"name": "orders", "owner": "orders"}],
  "access": [{"database": "orders", "role": "orders", "cidr": "10.0.0.0/16"}],
  "backup": {}
}
```

Without a name, `deployments create --file` takes the full request
(`name`, `type`, `instanceIDs`, `spec`). The README has the spec for each type.
`connection` prints credentials; capture it only where you mean to store them.

```sh
korta deployments restart dep_ID --wait
korta deployments rollback dep_ID --data '{"release":"RELEASE"}' --wait
korta deployments backup dep_ID --data '{"type":"full"}' --wait
korta deployments backups dep_ID
korta deployments restore dep_ID --data '{"confirm":"orders-db","target":"2026-10-30T10:00:00Z"}' --wait
```

Restore replaces the database's data and needs `confirm` set to the deployment
name, with a backup `set`, a `target` time, or both. PostgreSQL backups take a
`type` (`full`, `diff` or `incr`). `korta deployments action dep_ID ACTION`
runs any other action the deployment type offers.

## Roles

```sh
korta roles preview --markdown role.md
korta roles create --file role.md --name db-access --label env=prod
korta roles plan role_ID
korta roles apply role_ID --approve --wait
```

`preview` lists the steps the Markdown compiles to and exits 1 with the line
number of the first mistake, so it works as a CI check. `create` needs `--name`
and targets (`--instance ID` or `--label KEY=VALUE`, repeated or
comma-separated); `--description`, `--batch-size` and `--continue-on-failure`
are optional. `korta roles update role_ID --file role.md` replaces the Markdown
and keeps the name, description, targets and rollout unless you pass new ones.
`--file` also accepts a JSON role object.

`plan` changes nothing. It shows, for each instance, every step and whether it
would change. `apply --approve` applies the role's current plan, the one you just
reviewed, and prints which plan and risks it is approving. Pass `--plan op_ID` to
pin a specific plan. Roles with custom scripts also need `--confirm-commands`.
The manager rejects plans that are stale, older than 24 hours, or already applied.

## Secrets

```sh
korta secrets set db_password                    # asks for the value, hidden
korta secrets set tls_key --value-file app.key   # from a file
vault read -field=password kv/app | korta secrets set db_password   # from stdin
korta secrets list                               # names and the roles using them
korta secrets delete db_password                 # refused while a role uses it
```

Secrets live in the manager's vault and roles use them as `{{ secret.NAME }}`.
Values are never taken from arguments, which shells keep in their history, and
no command shows them again. Setting an existing name rotates it; plans made
before the rotation must be made again. Trailing newlines are removed. Offline,
`{{ secret.NAME }}` reads `KORTA_SECRET_NAME` from the environment instead.

## AI assistant

```sh
korta assistant status
korta assistant start --role role_ID
korta assistant send chat_ID --text 'Install nginx on staging hosts'
korta assistant save chat_ID
```

Saving creates or revises a role; plan and approve it as usual.

## Provisioning, activity and the API

```sh
korta provision --file provision.json --wait
korta operations list
korta operations wait op_ID --timeout 30m
korta api GET /api/health
```

`korta api METHOD /api/PATH [--data JSON]` calls any endpoint, including new ones
the CLI has no command for yet. Request bodies must be valid JSON of at most
1 MiB. Server settings such as the listen address and the Anthropic API key are
environment variables of `korta-server`, not API settings.

## AWS instance roles

A role that begins with `# AWS instance` creates its own EC2 instances (see
[AWS roles](roles.md#create-aws-instances-enterprise)). Create it without
target flags, then run it:

```sh
korta roles create --file web.md --name web
korta roles run role_ID                     # plans, shows the plan, asks to apply
korta roles run role_ID --approve           # the same without the prompt, for CI
korta roles destroy role_ID --confirm web   # plan and approve terminating them
```

`roles run` and `roles destroy` stop after the plan when the manager requires a
second approver; that person runs `korta roles apply role_ID --approve` (with
`--confirm NAME` for a destroy plan). AWS credentials are configured on the
manager, never in role files or command arguments.

## Inspect host networking

Use the standalone CLI to inspect the addresses and routes of an interface on
selected inventory hosts, without changing them:

```sh
korta network inspect eth0 -i hosts.md --limit env=staging
korta network inspect eth0 -i hosts.md --json
```

The output contains `iproute2` JSON for the interface and its IPv4 and IPv6
routes. Each host needs the `ip` command. Korta uses the same inventory, SSH
configuration, identity and `--timeout` options as offline role commands. A
failed host is reported and causes a nonzero exit status. This command does
not configure interfaces, DNS or routes.

## Copy a file to hosts

Copy a local regular file, including binary data, to an absolute path on each
selected inventory host:

```sh
korta copy ./config/app.conf /etc/app.conf -i hosts.md --limit staging --dry-run
korta copy ./config/app.conf /etc/app.conf -i hosts.md --limit staging
```

Korta inspects every destination before asking for confirmation. Use `--yes`
for unattended runs. `--owner`, `--group` and `--mode` set the destination
metadata; defaults are `root`, the chosen owner, and `0644`. The destination's
parent directory must exist. Korta refuses symlink and non-file destinations,
checks for changes since inspection, transfers through SSH stdin and replaces
the file atomically. It restores the SELinux label when `restorecon` is
available. A source changed during transfer or a destination changed since the
plan is refused. `--json` prints machine-readable results. An error on one host
is reported and returns a nonzero exit status.

This command uses the offline inventory and existing SSH configuration; it does
not send files through the Enterprise manager. Protect sensitive source files
on the local and remote hosts using appropriate permissions.

## Inspect a disk

To inspect one explicitly named block device on selected inventory hosts:

```sh
korta disk inspect /dev/disk/by-id/DEVICE -i hosts.md --limit staging
```

The device must have a serial number or WWN. This read-only probe currently
refuses a device with child devices; it does not partition, format or mount
storage. Use `--json` for machine-readable output.
