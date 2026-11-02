# Modules

A module is one kind of thing Korta manages on a host. You use a module by
writing a Markdown heading that names it, then one bullet per item. Korta
checks each item against the host, shows what would change, and applies only
the differences.

```markdown
# Packages
- nginx, curl

# Services
- nginx started, enabled, reload on change
```

Every module works the same way with `plan` and `apply`:

```sh
korta plan  role.md -i hosts.md --limit env=prod   # changes nothing
korta apply role.md -i hosts.md --limit env=prod   # plans, asks, applies
```

Each module below lists the heading that selects it and a minimal example. The
[Markdown roles](roles.md) guide has every option and the rules for each module.

## Module summary

| Module | Heading | Manages | Details |
| ------ | ------- | ------- | ------- |
| Users | `Users`, `Account` | Accounts, shells, groups, SSH keys | [Markdown roles](roles.md) |
| Groups | `Groups` | Groups | [Markdown roles](roles.md) |
| Directories | `Directories`, `Folder` | Directories, owner, group, mode | [Markdown roles](roles.md) |
| Files | `Files` | File content, templates, owner, mode, checks | [Markdown roles](roles.md) |
| Packages | `Packages`, `Software` | Install, remove or upgrade packages | [Markdown roles](roles.md) |
| Services | `Services` | Start, stop, enable, reload and restart | [Markdown roles](roles.md) |
| Kernel settings | `Kernel settings`, `Sysctl` | `sysctl` values | [Markdown roles](roles.md) |
| Firewall | `Firewall`, `Port` | Open and close ports, by source | [Markdown roles](roles.md) |
| Updates | `Updates`, `Patch` | Security and system updates, reboots | [Markdown roles](roles.md) |
| Hostname | `Hostname` | Static host name | [Markdown roles](roles.md) |
| Timezone | `Timezone` | Time zone | [Markdown roles](roles.md) |
| Time | `Time` | Network time synchronization | [Markdown roles](roles.md) |
| DNS | `DNS` | Resolver addresses | [Markdown roles](roles.md) |
| SELinux | `SELinux` | Mode, booleans, ports and file contexts | [Markdown roles](roles.md) |
| Scheduled jobs | `Scheduled jobs` | Cron jobs that run scripts | [Markdown roles](roles.md) |
| Commands | `Commands`, `Script` | Your own shell commands | [Markdown roles](roles.md) |
| Variables | `Variables`, `Vars` | Defaults for `{{ name }}` in any role | [Markdown roles](roles.md) |

## Users and groups

Create, change or remove accounts and groups. A user can carry its SSH keys.

```markdown
# Groups
- apps

# Users
- deploy added to apps group, shell /bin/bash
  - key ssh-ed25519 AAAA... deploy@laptop
- olduser removed
```

Korta creates groups that a user joins before the user, and the plan accounts
for both. Removing a user is flagged for review.

## Directories and files

Directories set owner, group and mode. Files set content, from the role or from
a template, and can run a check before they go live.

```markdown
# Directories
- /opt/app owned by app:apps, mode 0750

# Files
- /etc/motd, mode 0644
  ```
  Managed by Korta
  ```
- /etc/nginx/conf.d/site.conf from templates/site.conf, check with nginx -t
```

A file with `check with` is put in place, the check runs, and the previous
file is restored if the check fails. With `%s` in the command, the new content
is checked before it replaces the old file.

## Packages and services

```markdown
# Packages
- nginx, curl
- keep openssl at the latest version
- remove telnet

# Services
- nginx started, enabled, reload on change
- postfix stopped, disabled
```

`reload on change` and `restart on change` act only when an earlier step in the
same run changed the host, so a reload happens after the new config arrives.

## Kernel settings

```markdown
# Kernel settings
- net.core.somaxconn = 1024
```

Korta writes the values to a file in `/etc/sysctl.d`, applies them now, and
checks them on later runs.

## Firewall

```markdown
# Firewall
- open 443/tcp from anywhere
- open 5432/tcp from 10.0.0.0/8
- close 23 from anywhere
```

Closing a port and opening one from a narrow source are the safest ways to
tighten access. The plan flags port closures for review.

## Updates

```markdown
# Updates
- security updates, reboot if required, except kernel
```

Korta installs updates and reboots the host only if the role allows it. Reboots
and kernel changes are flagged for review in the plan.

## Hostname, time and DNS

```markdown
# Hostname
- web-01.example.com

# Timezone
- America/Phoenix

# Time
- ntp enabled

# DNS
- nameservers 1.1.1.1, 8.8.8.8
```

Each setting is reviewed in the plan before it changes. DNS changes apply only
to a regular, manually managed `/etc/resolv.conf`; hosts whose resolver is
managed by NetworkManager, systemd-resolved or resolvconf are refused with a
message that says which service to configure instead.

## SELinux

```markdown
# SELinux
- mode enforcing
- boolean httpd_can_network_connect on
- port tcp 8080 http_port_t
- fcontext /srv/web httpd_sys_content_t recursive
```

SELinux settings apply to hosts where SELinux is already enabled. Korta refuses
to enable or disable it, because that needs a planned reboot and relabeling.

## Scheduled jobs

```markdown
# Scheduled jobs
- clean-reports
  - schedule: 0 2 * * 0
  - user: app

  ```sh
  /usr/local/bin/clean-reports
  ```
```

Korta writes one cron file per job. Adding or changing a job needs command
confirmation (`--confirm-commands`).

## Commands

Run your own commands when no built-in module covers the task. Commands run as
root and need `--confirm-commands`.

```markdown
# Commands
- Install the agent unless /opt/agent exists

  ```sh
  curl -fsSL https://example.com/install.sh | sh
  ```
```

Use `unless` with a test so the command runs only when needed. Prefer a built-in
module whenever one exists, because modules are checked and reported in plans.

## Variables and templates

```markdown
# Variables
- domain = example.com

# Files
- /etc/app.conf from templates/app.conf
```

Set variables in the role, in the inventory (`vars:` lines), or on the command
line with `--var NAME=VALUE`. Values from the command line win, then the
inventory, then the role's defaults.

## Host tools

Some commands inspect a host without changing it. Use them to check a host
before you write a role.

| Command | What it does |
| ------- | ------------ |
| `korta inventory -i hosts.md` | Lists the hosts that a selector matches, with their keys and variables |
| `korta disk inspect DEVICE -i hosts.md` | Shows a block device by its stable ID |
| `korta network inspect eth0 -i hosts.md` | Shows an interface's addresses and routes |
| `korta copy SOURCE DEST -i hosts.md` | Copies one file to selected hosts, with `--dry-run` first |

See the [CLI reference](cli.md) for every flag.

## Enterprise modules

With a Korta Enterprise manager, roles can also create and
configure cloud instances and their networks:

- [AWS instances](roles.md#create-aws-instances-enterprise), with networks,
  load balancers and DNS names.
- [GCP instances](roles.md#create-gcp-instances-enterprise).

Databases and applications have their own deployment types: PostgreSQL, MySQL,
Node.js and Next.js. They are described in the Korta Enterprise documentation.
