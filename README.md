# Korta: configuration management in Markdown

Describe your servers in Markdown, see exactly what will change, and apply it
over SSH. No agents, no YAML. Hosts need only SSH with root or passwordless sudo.

```markdown
# Users
- test added to database group
- app user added to apps group

# Directories
- /opt/db owned by test, mode 0750
- /opt/app
```

```sh
korta plan  role.md -i hosts.md                   # changes nothing
korta apply role.md -i hosts.md --limit env=prod  # plans, asks, applies
```

## Requirements

**The machine that runs `korta`** (your laptop, a bastion or a CI runner):

- macOS or Linux, on amd64 or arm64.
- The OpenSSH client. Check with `ssh -V`; on Debian or Ubuntu install it with
  `sudo apt install openssh-client`. Korta uses your SSH setup:
  `~/.ssh/config`, ssh-agent and `~/.ssh/known_hosts`.

The Windows builds work with a [Korta Enterprise](#korta-enterprise) manager.
To run roles over SSH from Windows, use WSL.

**The hosts it configures:**

- Ubuntu 22.04 or 24.04, Debian 12 or 13, RHEL, Rocky Linux or AlmaLinux 8 to
  10, or CentOS Stream 9 or 10, on amd64 or arm64.
- SSH access with a key, as root or as a user with passwordless sudo. Cloud
  images usually set this up for their default user (`ubuntu`, `admin`,
  `ec2-user`, `rocky`).
- Nothing else: no agent, Python or package to install.

## Install

### From a release (recommended)

Download the archive for your system from the
[releases page](https://github.com/nexusrun/korta/releases), check it, and put
`korta` on your `PATH`:

```sh
VERSION=0.1.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')          # linux or darwin
ARCH=$(uname -m)
case $ARCH in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac
FILE=korta_${VERSION}_${OS}_${ARCH}.tar.gz

curl -fsSLO "https://github.com/nexusrun/korta/releases/download/v$VERSION/$FILE"
curl -fsSLO "https://github.com/nexusrun/korta/releases/download/v$VERSION/checksums.txt"
grep " $FILE\$" checksums.txt | shasum -a 256 -c -    # prints: OK

tar -xzf "$FILE"
sudo install -m 755 "korta_${VERSION}_${OS}_${ARCH}/korta" /usr/local/bin/korta
korta version
```

No `sudo`? Install it in your home instead with
`install -m 755 korta_*/korta ~/.local/bin/korta`, and put `~/.local/bin` on
your `PATH`. On macOS, a file downloaded with a browser rather than `curl` may
be blocked; allow it with `xattr -d com.apple.quarantine /usr/local/bin/korta`.

### With Go

With Go 1.26 or later:

```sh
go install github.com/nexusrun/korta/cmd/korta@latest
```

This puts `korta` in `$(go env GOPATH)/bin`; make sure that is on your `PATH`.

### From source

```sh
git clone https://github.com/nexusrun/korta.git
cd korta
make build          # writes bin/korta
```

### Upgrade or remove

To upgrade, repeat the installation with the new version. To remove Korta,
delete the binary (`sudo rm /usr/local/bin/korta`). Korta keeps only run logs,
in `~/.local/state/korta/runs/`.

## Get started

This walks through configuring a host from your machine. Replace the addresses
and users with your own.

**1. Check SSH.** Korta connects the way `ssh` does and never asks for a
password, so this must work without one. Connecting once also records the
host's key, which Korta requires:

```sh
ssh ubuntu@10.0.0.5 'sudo -n true && echo ready'
```

If it asks for a password, add your key to the host
(`ssh-copy-id ubuntu@10.0.0.5`), or load a key that has a passphrase into your
agent (`ssh-add ~/.ssh/id_ed25519`). If `sudo` asks for a password, give the
user passwordless sudo on the host, or connect as root.

**2. List your hosts** in `inventory.md`. Each heading is a group, each bullet
a host: a name, `user@address`, then `KEY=VALUE` labels:

```markdown
# Production
- db1 ubuntu@10.0.0.5 env=prod

# Staging
- web1 deploy@10.0.1.5 env=staging
```

Check what Korta reads:

```sh
korta inventory
```

**3. Describe what the hosts should have** in `site.md`:

````markdown
# Packages
- nginx, curl

# Services
- nginx started, enabled

# Files
- /etc/motd, mode 0644

```
Managed by Korta
```
````

**4. See what would change.** Planning connects to each host and changes
nothing:

```sh
korta plan site.md --limit env=staging
```

**5. Apply it.** Korta plans again, shows the changes, asks, then applies them
host by host, stopping at the first failure:

```sh
korta apply site.md --limit env=staging
```

Run it again and Korta finds nothing to change: roles describe the end state,
so applying twice is safe.

Without `-i`, Korta reads `inventory.md` in the current folder, or the file
named by `KORTA_INVENTORY`. `--limit` picks hosts by group, name or label. In
CI, add `--yes` to apply without a prompt. Groups can use their own SSH user
and key; see the [CLI reference](docs/cli.md#ssh-keys).

## When something fails

| Message | What to do |
| ------- | ---------- |
| Host key verification failed | Connect once with `ssh` to record the host's key, or update `~/.ssh/known_hosts` after a reinstall |
| Permission denied (publickey) | Add your key to the host, name it with `identity:` in the inventory, or load it with `ssh-add` |
| sudo: a password is required | Give the SSH user passwordless sudo, or connect as root |
| unsupported operating system | The host runs a system Korta does not support yet; see [Requirements](#requirements) |

Each apply writes a log with the plan and results to
`~/.local/state/korta/runs/`.

## Documentation

- [Roles in Markdown](docs/roles.md): everything a role can manage, with
  variables and templates.
- [CLI reference](docs/cli.md): the inventory format, SSH keys per group,
  variables, and host inspection commands.
- [Credentials](docs/credentials.md): SSH access for the CLI, and how cloud
  and manager credentials are used.
- [Releasing](docs/releasing.md): for maintainers.

`korta --help` lists every command, and `korta COMMAND --help` explains one.

## Korta Enterprise

Korta Enterprise adds a manager with a web console, PostgreSQL, MySQL and
Node.js deployments, plan approval and an audit log, AWS provisioning, and an
AI role assistant. The same `korta` CLI and role files work with it: sign in
with `korta login --server URL --token-file FILE`.

## Packages

| Package     | Purpose                                                    |
| ----------- | ---------------------------------------------------------- |
| `roles`     | Markdown role parser, step scripts, and the plan and apply engine |
| `inventory` | Markdown inventory parser and host selection               |
| `sshclient` | OpenSSH-based connections with strict host key checking    |
| `hostos`    | Operating system detection                                 |
| `cli`       | The `korta` command                                        |

## Development

```sh
make check   # gofmt, go vet and tests
make build   # writes bin/korta
```

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) to set up,
make a change and open a pull request; commits are signed off under the
[Developer Certificate of Origin](https://developercertificate.org). Report
security problems privately as described in [SECURITY.md](SECURITY.md), and
follow the [code of conduct](CODE_OF_CONDUCT.md).

## License

Korta is licensed under the [Apache License, Version 2.0](LICENSE).
Copyright 2026 The Korta Authors; see [NOTICE](NOTICE). Korta Enterprise is a
separate, commercial product.
