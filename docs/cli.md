# Korta CLI

`korta` runs Markdown roles on your hosts over SSH, straight from your machine
or from CI. Hosts come from a Markdown inventory, and SSH uses the keys and
settings you already have. No manager is needed.

For the SSH and cloud credentials each command uses, see
[Credentials](credentials.md).

Run `korta --help` for the overview and `korta COMMAND --help` for any command.
Help does not connect to a host or read your inventory.

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
