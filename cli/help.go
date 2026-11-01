package cli

const help = `korta: configuration management in Markdown

Usage: korta COMMAND [SUBCOMMAND] [ID] [flags]
       korta COMMAND [SUBCOMMAND] --help   Options and examples for one command

Run roles over SSH (no manager needed):
  plan ROLE.md -i hosts.md [--limit SELECTOR] [--var NAME=VALUE]
                                                Show what would change
  apply ROLE.md -i hosts.md [--limit SELECTOR] [--var NAME=VALUE] [--yes]
                   [--confirm-commands] [--batch-size N] [--continue-on-failure]
                                                Plan, confirm, then apply
  disk inspect DEVICE -i hosts.md               Inspect a stable disk ID
  copy SOURCE DEST -i hosts.md [--dry-run]      Copy a file to selected hosts
  network inspect INTERFACE -i hosts.md         Inspect interface addresses and routes
  inventory -i hosts.md [--limit SELECTOR]      List hosts with their keys
                                                and variables

Roles in Markdown (docs/roles.md):
  # Users, # Packages, # Files, # Services ...  Headings say what to manage;
                                                each bullet is one item
  # Variables  - domain = example.com           Defaults for {{ domain }}
  - /etc/app.conf from templates/app.conf       Content from a template file
  - /etc/nginx/conf.d/site.conf, check with nginx -t
                                                Keep the old file if it fails
  - nginx started, enabled, reload on change    Reload after earlier changes

Inventory in Markdown (docs/cli.md):
  # Production                                  A group; nested headings nest
  identity: ~/.ssh/prod_ed25519                 SSH key for the group
  user: ubuntu                                  SSH user for the group
  vars: domain=shop.example.com                 Variables for the group
  - db1 10.0.0.5 env=prod                       A host, with its own labels

The commands below need Korta Enterprise (a manager):

Sign in:
  login [--server URL] [--token-file FILE]   Check and save credentials
  logout                                     Remove saved credentials
  session | health | types | ca              Inspect the manager and its TLS CA

Instances:
  instances list | get ID | update ID | delete ID
  instances create NAME --host HOST --user USER --key KEY_ID [--port N]
                   [--host-key 'ssh-ed25519 ...'] [--label KEY=VALUE]
  instances check ID | trust-host-key ID
  instances console ID                       Interactive SSH session

Deployments (PostgreSQL, MySQL, Node.js and Next.js):
  deployments list | get ID | delete ID
  deployments create NAME --type TYPE --instance ID [--file SPEC.json]
  deployments update ID --file SPEC.json     Replace the spec
  deployments apply ID | restart ID | rollback ID | backup ID | restore ID
  deployments status ID | logs ID | backups ID   (these wait for the result)
  deployments action ID ACTION               Run any deployment action
  deployments connection ID [--role USER] [--database NAME]

Roles:
  roles list | get ID | delete ID
  roles create --file role.md --name NAME --label KEY=VALUE | --instance ID
  roles update ID --file role.md             Keeps name, targets and rollout;
                                             template files are sent along
  roles preview --markdown role.md           Show the steps; exits 1 on mistakes
  roles plan ID                              Show what would change (waits)
  roles run ID [--approve]                   Plan, then apply after you confirm
  roles destroy ID --confirm NAME            Terminate what the role created in AWS
  roles apply ID --approve [--plan PLAN_ID] [--confirm-commands]
                                             Apply the reviewed plan (default:
                                             the role's current plan)

Keys, secrets and activity:
  keys list | create NAME --private-key FILE | delete ID
  secrets list | set NAME [--value-file FILE] | delete NAME
                                             Vault values for {{ secret.NAME }}
  operations list | get ID | wait ID
  audit [--target ID]

AI assistant:
  assistant status | start [--role ROLE_ID]
  assistant send CHAT_ID --text 'instructions'
  assistant save CHAT_ID

Other:
  provision --file FILE                      Register a host and deploy to it
  api METHOD /api/PATH [--data JSON]         Call any API endpoint
  version

Flags (before or after the command):
  --file, -f FILE      JSON request, role Markdown or spec; - reads stdin
  --data JSON          Inline JSON instead of --file
  --markdown FILE      Role Markdown; - reads stdin
  --name, --description, --batch-size N, --continue-on-failure
                       Role settings for roles create and update
  --instance ID        Target instance; repeat or comma-separate
  --label KEY=VALUE    Target or instance label; repeat or comma-separate
  --wait               Wait for the operation and show its steps; a failed
                       operation exits 1. --wait=false returns at once
  --json               JSON output for scripts (same as --output json)
  --output FORMAT      table (default) or json
  --server URL         Manager URL (default http://127.0.0.1:8080)
  --token-file FILE    Read the admin token from a file
  --insecure           Allow sending the token over plain HTTP to another host
  -i, --inventory FILE Markdown inventory (default: KORTA_INVENTORY, ./inventory.md)
  --limit SELECTOR     Group heading, host name or KEY=VALUE; repeat or comma-
                       separate to select more hosts
  --yes                Apply without the confirmation prompt
  --ssh-config FILE    Use this file instead of ~/.ssh/config (KORTA_SSH_CONFIG)
  -k, --identity FILE  Private key for every selected host, overriding the
                       inventory (KORTA_IDENTITY)
  --var NAME=VALUE     Role variable for this run, over the inventory and the
                       role's defaults; repeat for more. ${NAME} in any value
                       is read from the environment
  --config FILE        Credentials file (default: user config dir/korta/config.json)
  --timeout DURATION   Deadline for the command and its waiting (default 10m);
                       consoles and offline plan and apply have none
  --help, -h           Show this help

Environment: KORTA_SERVER, KORTA_TOKEN, KORTA_CONFIG, KORTA_INVENTORY,
KORTA_SSH_CONFIG, KORTA_IDENTITY.
Precedence: flags, then environment, then saved credentials, then defaults.
Saved credentials are only sent to the manager they were saved for. The token
is never sent over plain HTTP to another machine without --insecure.
Nothing is approved automatically: plans never change hosts, applying through
a manager needs --approve, and offline apply asks first (or needs --yes).
`
