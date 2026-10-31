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
make build
./bin/korta plan  role.md -i hosts.md                 # changes nothing
./bin/korta apply role.md -i hosts.md --limit env=prod   # plans, asks, applies
```

Hosts come from a Markdown inventory. Each group can use its own SSH user and
key, and SSH otherwise uses your own `~/.ssh/config`, ssh-agent and `known_hosts`:

```markdown
# Production
identity: ~/.ssh/prod_ed25519
- db1 ubuntu@10.0.0.5 env=prod

# Staging
identity: ${STAGING_SSH_KEY}
- web1 deploy@web1.internal env=staging
```

Supported hosts: Ubuntu 22.04 and 24.04, Debian 12 and 13, RHEL, Rocky Linux and
AlmaLinux 8 to 10, and CentOS Stream 9 and 10.

## Documentation

- [Roles in Markdown](docs/roles.md): everything a role can manage.
- [CLI guide](docs/cli.md): offline mode, the inventory format, and the commands
  for Korta Enterprise.

## Korta Enterprise

Korta Enterprise adds a manager with a web console, PostgreSQL, MySQL and
Node.js deployments, plan approval and an audit log, and an AI role assistant.
The same `korta` CLI and role files work with it.

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
```
