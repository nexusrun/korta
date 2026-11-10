# Roles in Markdown

A role describes how hosts should look. Each heading says what its section
manages, each bullet is one item, and code blocks hold file contents and
scripts. Other text is notes. Anything Korta cannot read is an error with its
line number: a role never guesses.

~~~markdown
# Users
- deploy added to apps group, shell /bin/bash
  - key ssh-ed25519 AAAA... you@laptop

# Directories
- /opt/app owned by deploy:apps, mode 0750

# Files
- /etc/motd, mode 0644

```
Managed by Korta
```

# Packages
- nginx, curl

# Services
- nginx started, enabled, restart on change
~~~

The first matching word in a heading decides what the section manages, so
`# Create users` is a Users section. Steps run in order, and every step only
changes what differs from the description.

| Section         | Bullets                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| Users           | `deploy added to apps group, shell /bin/bash`; nested `- key ssh-ed25519 ...`; `remove olduser` |
| Groups          | `apps`, `builders (system)`, `remove legacy`                            |
| Directories     | `/opt/app owned by app:apps, mode 0750` (default root, 0755)            |
| Files           | `/etc/motd, mode 0644` with the content in a code block below; `remove /etc/old.conf` |
| Repositories    | `docker` with `url:`, `key:` and `fingerprint:` bullets; `remove docker` (see below) |
| Downloads       | `/usr/local/bin/tool from https://...` with a `sha256:` bullet; `remove /usr/local/bin/tool` (see below) |
| Packages        | `nginx, curl`; `keep openssl at the latest version`; `remove telnet`    |
| Services        | `nginx started, enabled, restart on change`; `postfix stopped, disabled` |
| Kernel settings | `net.core.somaxconn = 1024`                                             |
| Firewall        | `open 443/tcp from 10.0.0.0/8`; `close 23 from anywhere`                |
| Updates         | `security updates, reboot if required, except kernel`                   |
| Commands        | a code block, optionally under `- Install the agent unless /opt/agent exists` |
| Hostname        | `web-01.example.com` sets the static hostname using `hostnamectl` |
| Time            | `timezone America/Phoenix`; `ntp enabled` or `ntp disabled` using `timedatectl` |
| DNS             | `nameservers 1.1.1.1, 8.8.8.8` for manually managed resolver files |
| Variables       | `domain = example.com`: defaults for `{{ domain }}` (see below)         |
| SELinux         | `mode enforcing`; `boolean httpd_can_network_connect on`; `port tcp 8080 http_port_t`; `fcontext /srv/web httpd_sys_content_t recursive` |
| Scheduled jobs  | `clean-reports` with `schedule: 0 2 * * 0`, `user: app`, and a script in a code block |

A Files bullet can end with `check with COMMAND`. Korta puts the new file in
place, runs the command, and puts the previous file back if it fails, so a bad
config never stays live. With `%s` in the command, the new content is checked
before it replaces the old file instead: `check with visudo -cf %s`. Services
take `reload on change` (reload, for example nginx without dropping
connections) or `restart on change`, applied when an earlier step changed the
host.

Groups that users join are created first when no earlier step manages them.
Plans account for users and groups that earlier steps would create.

Removing users, groups or packages, closing ports, rebooting, and custom scripts
are flagged for review. Custom scripts run as root and need `--confirm-commands`
to apply.

## Variables and templates

`{{ name }}` works anywhere in a role: file contents, paths, packages, ports.
Korta fills it in separately for each host before compiling the role:

~~~markdown
# Variables
- app_port = 3000

# Packages
- nginx

# Files
- /etc/nginx/conf.d/{{ domain }}.conf, mode 0644, check with nginx -t

```nginx
server {
    listen 80;
    server_name {{ domain }};
    location / {
        proxy_pass http://127.0.0.1:{{ app_port }};
    }
}
```

# Services
- nginx started, enabled, reload on change
~~~

Values come from, highest first:

1. `--var name=value` on the command line.
2. The host's `KEY=VALUE` labels in the inventory.
3. Its group's `vars:` line in the inventory.
4. The role's `# Variables` section.

Built-in facts are always available: `{{ host.name }}`, `{{ host.address }}`,
`{{ os.distro }}`, `{{ os.version }}`, `{{ os.family }}` (apt or rpm) and
`{{ os.arch }}`.

### Template files

Long configs can live in their own files, next to the role:

```markdown
# Files
- /etc/nginx/nginx.conf, mode 0644, from templates/nginx.conf, check with nginx -t
- /etc/helm/values.yaml from files/values.yaml, raw
```

`from` names a file relative to the role file's folder; it cannot leave that
folder. The file uses the same `{{ }}` variables, and mistakes in it are reported
with its own name and line. `raw` copies the file exactly. korta reads template
files when it runs a role, and `korta roles create` and `update` send them to
Korta Enterprise with the role. A role and its template files may total 1 MiB.

Rules that keep roles predictable:

- A variable without a value fails that host's plan with its line number. It is
  never left empty.
- Only plain names: no expressions, filters, loops or conditions. Hosts that
  need different content belong in different groups or roles.
- A code block marked `raw` (```` ```text raw ````) is copied exactly, for files
  that contain `{{ }}` themselves.
- `${NAME}` in a value comes from the environment of the machine running korta,
  for secrets: `db_password=${DB_PASSWORD}`. A missing one is an error.
- Plans and run logs never show rendered values; the log keeps the template.

### Secrets

`{{ secret.NAME }}` is a secret, such as a password or a TLS key:

~~~markdown
# Files
- /etc/app/env, mode 0600

```
DB_PASSWORD={{ secret.db_password }}
```

- /etc/ssl/private/app.key, mode 0600, from tls/app.key
~~~

where `tls/app.key` contains `{{ secret.tls_key }}`.

- Offline, korta reads `KORTA_SECRET_DB_PASSWORD` from the environment.
- With Korta Enterprise, the manager reads it from its vault
  (`korta secrets set db_password`).
- Secrets cannot be set in the inventory, with `--var` or through labels.
- Values that span lines, such as keys and certificates, go in template files;
  in the role's Markdown, values must be single lines.
- Values are never stored in roles, plans or logs, and are replaced with
  `[secret]` in step output and errors if a command prints them.

### With Korta Enterprise

Each instance's labels are its variables, over the role's `# Variables`
defaults, and host facts work the same way. A saved role shows its steps with
default values. Planning compiles it for every instance, and approving applies
exactly what was planned: if an instance's labels or a secret it uses change
after the plan, that instance is refused until you plan again. Saving a role
fails if it uses a secret the vault does not have, and a secret a role uses
cannot be deleted. `${NAME}` is not expanded on the manager; use secrets.

Check a role without touching any host:

```sh
korta roles preview --markdown role.md     # with Korta Enterprise
korta plan role.md -i hosts.md             # offline, read-only on the hosts
```

## Create AWS instances from the core CLI

The core CLI can create EC2 instances and configure them using one role. Set up
AWS credentials through an AWS profile, environment variables, or an IAM role,
and set a region in the role or the AWS configuration. For example:

```markdown
# AWS instance
- name: web
- count: 2
- region: us-east-1
- os: ubuntu 24.04
- size: t3.small

# Firewall
- open 443/tcp from anywhere

# Packages
- nginx
```

```sh
korta plan web.md
korta apply web.md
```

The plan resolves the account, image, VPC, subnets and access rules and performs
an EC2 dry run. It creates no cloud resources. Configuration steps cannot be
inspected until the host is reachable; apply shows a host plan before making
host changes. New AWS resources may incur charges. Apply prompts before cloud
changes and again before host changes; `--yes` accepts both prompts. Custom
scripts and checks also require `--confirm-commands`.

When the role has firewall steps and neither UFW nor firewalld is active,
Korta enables UFW after allowing the current SSH source and the role's open
ports. It installs UFW on apt-based hosts if needed, and schedules a rollback
until it verifies a fresh SSH connection. See [AWS setup](aws.md) for source
address changes and recovery.

Core uses the default VPC unless the role supplies a subnet. It creates an SSH
key pair and, unless security groups are supplied, a security group allowing
SSH from the caller's public IP and the role's firewall ports. Private addresses
require network access from the CLI machine. The first SSH host key is trusted
on first use, displayed and pinned; verify the fingerprint independently when
possible. Later key changes are rejected.

Korta stores a private key, launch reservations and pinned host keys under
`$XDG_STATE_HOME/korta/aws`, or `~/.local/state/korta/aws` by default. Back up
this private state securely. Reapply the same role after an interrupted run to
recover its instances. Count can grow but cannot shrink; changing existing launch
settings or moving or renaming the role requires a separate migration. Deleting
the role or local state does not terminate AWS resources. Inspect AWS directly
to manage or remove them.

This first core version supports EC2 creation and host configuration. Manager
network presets, custom key pairs, static IPs, load balancers, DNS, standalone
AWS network roles and JSON apply output are not supported. It runs on Linux and
macOS. AWS fields remain literal values, and secrets and credentials must not be
included in the AWS section.

## Create AWS instances (Enterprise)

With a Korta Enterprise manager, a role can create its own EC2 instances: begin
it with `# AWS instance` and put host configuration below. A name is enough:

```markdown
# AWS instance
- name: web
- count: 2
- os: ubuntu 24.04
- size: t3.small

# Firewall
- open 443/tcp from anywhere

# Packages
- nginx
```

| Field     | Default            | Meaning |
| --------- | ------------------ | ------- |
| `name`    | required           | Instance name; with a count, `web`, `web-2`, `web-3` |
| `count`   | `1`                | Instances to create, up to 20. It can grow later, never shrink |
| `os`      | `ubuntu 24.04`     | Ubuntu 22.04/24.04, Debian 12/13, RHEL, Rocky or AlmaLinux 8 to 10, CentOS Stream 9/10. Korta uses the newest official image |
| `size`    | `t3.micro`         | EC2 instance type (`instance-type` also works); Arm types get Arm images |
| `network` | the default VPC    | A network an admin defined on the manager, such as `prod` |
| `region`  | the manager's      | AWS region, such as `eu-west-1` |
| `address` | `public`           | `private` when the manager reaches the VPC privately |
| `static ip` | `no`             | `yes` gives each instance an Elastic IP that survives stop and start; can be switched later |

The manager picks the image and login user, spreads instances over the
network's subnets, creates an SSH key and a security group that allows SSH from
the manager plus the ports your `# Firewall` section opens, and keeps that group
in step with the role. To use your own resources instead, set `image` and
`user`, `subnet`, `security-groups` (up to 5), or `key-pair` with the matching
vault `ssh-key`.

AWS fields are literal `field: value` bullets: no variables or secrets. The
section comes first. Credentials belong to the manager, never to a role.

```sh
korta roles create --file web.md --name web
korta roles run role_ID                    # plan, review, approve
korta roles destroy role_ID --confirm web  # terminate what it created
```

The plan creates nothing; it shows the image, subnets and access Korta chose
and checks launch permission with a dry run. Approval creates the instances,
waits for SSH and configures them. Running the role again configures them and
launches more if `count` grew. Destroy is planned and approved like any change,
then terminates the instances and deletes the security group and key pair.
Core `korta plan` and `korta apply` also support a standalone EC2 workflow, as described above.

### Load balancers

A `# AWS load balancer` section right after `# AWS instance` puts an
Application Load Balancer in front of the instances: `listen` (`http`, or
`https` with an ACM `certificate`), `forward` (the instances' port, default
80), `health check` (default `/`), `from` (default `0.0.0.0/0`) and
`internal` (default `no`). It can be added, changed or removed later.

### DNS names

An `# AWS DNS` section lists names for the role, one per bullet, such as
`- shop.example.com`. Korta puts them in the account's matching Route 53
zone, pointing at the load balancer or the instances. With
`certificate: auto` on the load balancer, Korta requests and validates an
ACM certificate for these names.

### AWS networks

A role with only a `# AWS network` section builds a VPC, or adopts an existing
one, for instance roles to use with `network: NAME`:

```markdown
# AWS network
- name: prod
- region: eu-west-1
- cidr: 10.20.0.0/16
- zones: 3
- nat: per-zone
```

| Field             | Default        | Meaning |
| ----------------- | -------------- | ------- |
| `name`            | required       | What instance roles name with `network:` |
| `cidr`            | `10.0.0.0/16`  | A new VPC's range, /16 to /24 |
| `vpc`             | none           | Adopt this existing VPC instead of creating one |
| `zones`           | `2`            | Availability zones, 1 to 6; can grow later |
| `public subnets`  | carved         | One range per zone, existing subnet IDs (adopted VPCs only), or `none` |
| `private subnets` | carved         | The same for private subnets |
| `nat`             | `one`          | NAT gateways for private subnets: `one`, `per-zone` or `none` |
| `region`, `account` | the default  | Where the network goes |
| `ssh from`        | the manager    | Networks allowed to SSH to the instances |

Without listed ranges, public subnets take the lower half of the VPC range and
private subnets the upper half, a sixteenth each. In an adopted VPC, Korta
only adds its own subnets, gateways and routes, never changes what was there,
and Destroy removes only what it created. Instances with `address: private`
go to the private subnets, others to the public ones.

## Hostname, time and DNS

```markdown
# Hostname
- web-01.example.com

# Time
- timezone America/Phoenix
- ntp enabled

# DNS
- nameservers 1.1.1.1, 8.8.8.8
```

The hostname and time steps use `hostnamectl` and `timedatectl` on systemd
hosts. Timezones must be installed in `/usr/share/zoneinfo`. Enabling NTP asks
`timedatectl` to enable the host's configured time-synchronization service; it
does not choose or install one. A hostname or timezone can also be written in
its own `# Hostname` or `# Timezone` section. A role may contain one step for
each setting.

DNS accepts one to three distinct IPv4 or IPv6 unicast nameserver addresses.
It updates nameserver lines in a regular, manually managed `/etc/resolv.conf`,
preserving unrelated lines. Korta refuses symlinked resolver files and hosts
with active NetworkManager, systemd-resolved or resolvconf; configure those
services instead. Do not use this step if another service manages the file.
The plan reports DNS and hostname changes for review. Set appropriate resolver
addresses for your own environment; the addresses above are examples.

### Package repositories

Add a repository to install software your distribution does not ship. Put the
section above the Packages section that installs from it.

```markdown
# Repositories
- docker
  - url: https://download.docker.com/linux/{{ os.distro }}
  - key: https://download.docker.com/linux/{{ os.distro }}/gpg
  - fingerprint: 9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88
  - components: stable

# Packages
- docker-ce
```

| Field | Meaning |
| ----- | ------- |
| `url` | The repository's `https://` address |
| `key` | The `https://` address of its signing key, armored or binary |
| `fingerprint` | The key's full 40-character fingerprint, from the publisher's documentation. Separate several with commas |
| `suite` | apt only. Default: the host's release codename, such as `noble` |
| `components` | apt only. Default: `main` |

`fingerprint` is required. Korta downloads the key, and adds the repository
only if the key file holds exactly the listed keys. A different or additional
key fails the step and changes nothing. The plan flags every repository for
review, because its publisher can install software as root.

On dnf hosts, write the full path in `url`. `$releasever` and `$basearch` are
passed to dnf as they are:

```markdown
# Repositories
- docker
  - url: https://download.docker.com/linux/rhel/$releasever/$basearch/stable
  - key: https://download.docker.com/linux/rhel/gpg
  - fingerprint: 060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35
```

apt and dnf addresses differ, so keep apt and dnf hosts in separate roles, or
set the address per group with a variable. `suite`, `components`, and dnf
variables on the wrong kind of host are errors, not ignored.

Korta manages two files per repository and leaves others alone:
`/etc/apt/sources.list.d/xela-NAME.sources` with
`/etc/apt/keyrings/xela-NAME.gpg`, or `/etc/yum.repos.d/xela-NAME.repo` with
`/etc/pki/rpm-gpg/RPM-GPG-KEY-xela-NAME`. The key is trusted for this
repository only. After writing them, Korta reads the repository once. If that
fails, it puts the previous files back and reports the package manager's
error.

- Applying needs `gpg` and `curl` or `wget` on the host. Minimal Debian and
  Ubuntu images lack them: list `gnupg, curl` under a Packages heading above
  the repository.
- `remove docker` deletes both files. Installed packages stay, and on dnf
  hosts a key that dnf already imported stays in the rpm database.
- Addresses with a user name, password or token are not supported, and neither
  are plain `http://` mirrors.

### Downloads

Install a file that is not packaged, such as a release binary:

```markdown
# Downloads
- /usr/local/bin/node_exporter from https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-{{ os.arch }}.tar.gz
  - sha256 amd64: 6809dd0b3ec45fd6e992c19071d6b5253aed3ead7bf0686885a51d85c6643c66
  - sha256 arm64: 627382b9723c642411c33f48861134ebe893e70a63bcc8b3fc0619cd0bfac4be
  - extract: node_exporter-1.8.2.linux-{{ os.arch }}/node_exporter
  - mode: 0755
- /opt/app/app.jar from https://example.com/releases/app-2.4.jar
  - sha256: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
  - owner: app:apps
```

| Field | Meaning |
| ----- | ------- |
| `sha256` | The SHA-256 of the downloaded file, from the publisher's checksum list. Use `sha256 amd64` and `sha256 arm64` when the file differs by architecture |
| `extract` | Install this one file from a `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.tar.bz2`, `.tar.zst` or `.zip` download. Without it, the downloaded file itself is installed |
| `owner`, `group` | Default: `root`. `owner: app:apps` sets both |
| `mode` | Default: `0644`. Use `0755` for programs |

`sha256` is required and is always the checksum of what is downloaded, the
archive when `extract` is used. On a mismatch the step fails and the existing
file stays. To upgrade, change the address and the checksum together.

A plan never downloads. It compares the file on the host with the checksum,
so a file changed by hand is reported and replaced on the next apply. For an
extracted file, Korta keeps a small record under `/var/lib/xela/downloads`.
The plan flags every download for review.

- The host needs `curl` or `wget`, plus `tar` or `unzip` for `extract`. List
  missing ones under a Packages heading above the downloads.
- The address must be `https://`, without a user name, password or query.
- Korta installs the file and nothing else: add a Services section to restart
  what uses it, with `restart on change`.
- `remove /usr/local/bin/tool` deletes the file and its record.

### Scheduled jobs

Use a scheduled job to run a script through the host's cron service. Install and
start cron separately. The five numeric fields are minute, hour, day of month,
month and day of week, using the host's timezone. Ranges, lists and steps are
supported. The default user is `root`. Adding or changing a job needs command
confirmation, just like command steps; removing one does not.

````markdown
# Scheduled jobs
- clean-reports
  - schedule: 0 2 * * 0
  - user: app

  ```sh
  /usr/local/bin/clean-reports
  ```
````

Korta manages one file per job, `/etc/cron.d/xela-JOB`, and leaves other cron
files alone. To remove a job, use the same role and job name with `state: absent`
and omit the schedule, user and script. Scheduled scripts can't use
`{{ secret.NAME }}`, and cron files are readable by local users, so do not put
credentials in them.

### SELinux

Manage SELinux on hosts where it is already enabled:

```markdown
# SELinux
- mode enforcing
- boolean httpd_can_network_connect on
- port tcp 8080 http_port_t
- fcontext /srv/web httpd_sys_content_t recursive
```

The mode is `enforcing` or `permissive`, and is applied now and in
`/etc/selinux/config`. Boolean values are `on` or `off` and persist across
reboots. Port types apply to a single TCP or UDP port. If a port belongs to a
range with a different type, Korta refuses the change; adjust the range
manually. File context paths must exist; `recursive` includes descendants.
Korta creates or updates a local policy mapping and runs `restorecon`.

Install the host's SELinux management tools, including `semanage` and
`restorecon`, before using these steps. Korta refuses disabled SELinux: enabling
or disabling it requires a separately planned reboot and relabeling. Review
permissive mode carefully, since SELinux logs violations without enforcing them.

## Create GCP instances (Enterprise)

The manager creates Compute Engine instances and then runs the remaining role
steps over SSH. The manager uses Google Application Default Credentials; enable
the Compute Engine API and give those credentials permission to read the
project, image, machine type and subnet and create instances. No credentials
belong in the role. For local development, set up Application Default
Credentials with `gcloud auth application-default login`.

```markdown
# GCP instance
- name: web
- project: my-gcp-project
- zone: us-central1-a

# Packages
- nginx
```

Create the role through the Enterprise console or with `korta roles create
--name web --file web.md`, then plan and approve it. A plan resolves and shows
the image and subnet. GCP does not provide an EC2-style launch dry run, so a
successful plan does not prove that instance creation is permitted. A new
host's configuration is checked after creation.

The defaults are one `e2-micro` instance, the Ubuntu 24.04 image family, the
project's `default` subnet, user `korta`, and an ephemeral public address.
Set `count`, `size`, `image-project`, `image-family`, `subnet-project`,
`subnet`, `user`, or `address: private` to override them. Private addresses
require a route from the manager. The subnet and firewall must already exist
and allow SSH from the manager; Korta does not create GCP firewall rules.
Instance metadata SSH keys must be permitted. OS Login and organization
policies requiring it are not supported by this workflow. Korta checks the
project metadata but cannot determine every organization policy in advance.

An interrupted create retains a reservation and retries with the same GCP
request ID. Configuration failures retain the VM for inspection and retry.
Korta does not yet destroy GCP VMs; delete a VM in Google Cloud first, then
remove it from Korta. Do not remove an unresolved launch reservation before
recovering its outcome. Boot disks are configured for automatic deletion with
their VM.
