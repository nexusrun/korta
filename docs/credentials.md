# Credentials

The core CLI connects to your hosts with OpenSSH, using your own keys and
settings. It never stores private keys, and it never asks for them. This page
covers the credentials each command uses.

## SSH access to hosts

Each host needs a key it accepts, and either passwordless sudo or a root login.

Create a key for Korta and install its public half on a host:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/korta_ed25519 -C korta
ssh-copy-id -i ~/.ssh/korta_ed25519.pub ubuntu@10.0.0.5
ssh -i ~/.ssh/korta_ed25519 ubuntu@10.0.0.5 'sudo -n true && echo ready'
```

The last command must print `ready` without asking for a password. Connecting
once also records the host's key in `~/.ssh/known_hosts`. Korta refuses hosts
whose key is missing or has changed.

Name the key in your inventory. An `identity:` line applies to a whole group,
and `identity=` applies to one host:

```markdown
# Production
identity: ~/.ssh/korta_ed25519
user: ubuntu
- db1 10.0.0.5

# Staging
identity: ${STAGING_SSH_KEY}
user: deploy
- web1 10.1.0.5
```

Korta checks every key file before connecting. Key files need mode `600`
(`chmod 600 ~/.ssh/korta_ed25519`). A key with a passphrase must be loaded
first with `ssh-add ~/.ssh/korta_ed25519`, because SSH runs in batch mode and
never prompts.

| Setting | Flag | Environment | Use |
| ------- | ---- | ----------- | --- |
| Private key for every host | `--identity FILE`, `-k` | `KORTA_IDENTITY` | Override the inventory, for example in CI |
| SSH config | `--ssh-config FILE` | `KORTA_SSH_CONFIG` | Replace `~/.ssh/config`, for example with a committed `known_hosts` |
| Inventory | `-i FILE` | `KORTA_INVENTORY` | Choose the host list |

The full order of precedence and a CI example are in the [CLI reference](cli.md#ssh-keys).

## Cloud credentials

The core CLI doesn't use AWS or Google Cloud credentials. Roles that create
AWS or GCP instances need a Korta Enterprise manager, which signs in to your
cloud accounts itself. The CLI refuses those roles offline and explains that a
manager is required.

## Korta Enterprise sign-in

When you use a Korta Enterprise manager, sign in with a token:

```sh
korta login --server https://korta.example.com --token-file ~/.korta-token
```

Korta saves the token in your user configuration directory with mode `600`,
and sends it only to the manager it was saved for. Use `https://` for any
manager on another machine. The `--insecure` flag allows plain HTTP on a
network you trust.
