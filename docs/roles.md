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
| Packages        | `nginx, curl`; `keep openssl at the latest version`; `remove telnet`    |
| Services        | `nginx started, enabled, restart on change`; `postfix stopped, disabled` |
| Kernel settings | `net.core.somaxconn = 1024`                                             |
| Firewall        | `open 443/tcp from 10.0.0.0/8`; `close 23 from anywhere`                |
| Updates         | `security updates, reboot if required, except kernel`                   |
| Commands        | a code block, optionally under `- Install the agent unless /opt/agent exists` |
| Variables       | `domain = example.com`: defaults for `{{ domain }}` (see below)         |

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
Offline `korta plan` and `korta apply` refuse AWS sections.
