package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type commandHelp struct{ usage, summary, flags, example string }

const inputHelp = `  --file, -f FILE  Request JSON file; - reads stdin
  --data JSON      Inline JSON instead of --file
`

const roleHelpFlags = `  --file, -f FILE       Role Markdown or JSON; - reads stdin
  --markdown FILE       Explicit Markdown input; - reads stdin
  --name NAME           Role name (required when creating from Markdown)
  --description TEXT    Role description
  --instance ID         Target instance; repeat or comma-separate
  --label KEY=VALUE     Target label; repeat or comma-separate
  --batch-size N        Hosts per batch (1-100)
  --continue-on-failure Continue after a failed batch
`

const localHelpFlags = `  -i, --inventory FILE  Markdown inventory (KORTA_INVENTORY or ./inventory.md)
  --limit SELECTOR      Group, host or KEY=VALUE; repeat or comma-separate
  -k, --identity FILE   Private key for every host, over the inventory (KORTA_IDENTITY)
  --ssh-config FILE     SSH config (KORTA_SSH_CONFIG or ~/.ssh/config)
`

const varHelpFlags = `  --var NAME=VALUE      Role variable, over the inventory and # Variables;
                        repeat for more; ${NAME} reads the environment
`

const managerHelpFlags = `  --server URL       Manager URL (default http://127.0.0.1:8080)
  --token-file FILE  Admin token file
  --config FILE      Credentials file (KORTA_CONFIG or user config dir/korta/config.json)
  --insecure         Allow token over plain HTTP to a remote host
`

const outputHelpFlags = `  --json             JSON output for scripts
  --output FORMAT    table (default) or json
  --timeout DURATION Command deadline (default 10m; no default for consoles/offline runs)
  --help, -h         Show help for this command
`

// Detailed help is indexed by the same command paths used by the router.
var commandDetails = map[string]commandHelp{
	"instances create":         {"[NAME] --host HOST --user USER --key KEY_ID [flags]", "Register a host and check its SSH connection. JSON input is also accepted.", inputHelp + "  --host HOST      SSH host or IP address\n  --user USER      SSH login user\n  --key KEY_ID     Stored SSH key ID\n  --port N         SSH port (default 22)\n  --host-key KEY   Pinned SSH public host key\n  --label KEY=VALUE Instance label; repeat or comma-separate\n  --name NAME     Alternative to positional NAME\n", "korta instances create db1 --host 10.0.0.5 --user ubuntu --key key_ID --wait"},
	"instances update":         {"ID --file instance.json", "Update an instance using its JSON configuration.", inputHelp, "korta instances update ins_ID --file instance.json --wait"},
	"instances check":          {"ID", "Check SSH connectivity and refresh host information.", "", "korta instances check ins_ID --wait"},
	"instances trust-host-key": {"ID", "Replace the pinned SSH host key after a known host change.", "", "korta instances trust-host-key ins_ID --wait"},
	"instances console":        {"ID", "Open an interactive SSH terminal through the manager. Uses the stored key and pinned host key; resizes with your terminal. No default timeout.", "", "korta instances console ins_ID"},
	"deployments create":       {"[NAME] --type TYPE --instance ID [--file spec.json]", "Create a PostgreSQL, MySQL, Node.js or Next.js deployment. Also accepts a complete JSON deployment request.", inputHelp + "  --type TYPE    postgres, mysql, node or nextjs\n  --instance ID  Target instance; repeat or comma-separate\n  --name NAME    Alternative to positional NAME\n", "korta deployments create orders --type postgres --instance ins_ID --file spec.json --wait"},
	"deployments update":       {"ID --file spec.json", "Replace the deployment spec and apply it. Supply the spec alone, without a spec wrapper.", inputHelp, "korta deployments update dep_ID --file spec.json --wait"},
	"deployments action":       {"ID ACTION [--file args.json]", "Invoke any action supported by the deployment engine.", inputHelp, "korta deployments action dep_ID backup --data '{\"type\":\"full\"}' --wait"},
	"deployments connection":   {"ID [--role USER] [--database NAME]", "Get database connection details, including credentials.", "  --role USER      Database role or user\n  --database NAME  Database name\n", "korta deployments connection dep_ID --role orders --database orders"},
	"deployments logs":         {"ID [--data JSON]", "Read application logs. Waits for the result by default; use --wait=false to return immediately.", inputHelp, "korta deployments logs dep_ID --data '{\"lines\":100}'"},
	"deployments rollback":     {"ID [--data JSON]", "Roll an application back to a release supported by its engine.", inputHelp, "korta deployments rollback dep_ID --data '{\"release\":\"RELEASE_NAME\"}' --wait"},
	"deployments backup":       {"ID [--data JSON]", "Create a database backup. PostgreSQL accepts type full, diff or incr; omit type for MySQL.", inputHelp, "korta deployments backup dep_ID --wait"},
	"deployments restore":      {"ID --file restore.json", "Restore database data. JSON must include confirm matching the deployment name, and a backup set and/or RFC 3339 target time.", inputHelp, "korta deployments restore dep_ID --data '{\"confirm\":\"orders-db\",\"target\":\"2026-10-30T10:00:00Z\"}' --wait"},
	"roles create":             {"--file role.md --name NAME [--instance ID | --label KEY=VALUE]", "Create a role directly from Markdown, including extensionless files, or a JSON role request. Template files named with from are sent along. Roles beginning with AWS instance create and configure their own instance, without target flags. Saving does not run it.", roleHelpFlags + "  --data JSON           Inline JSON role request\n", "korta roles create --file role.md --name web-packages --label env=prod"},
	"roles update":             {"ID --file role.md", "Update a role from Markdown or JSON. Markdown updates preserve existing metadata unless overridden; target flags replace the target selection. Template files named with from are sent along.", roleHelpFlags + "  --data JSON           Inline JSON role request\n", "korta roles update role_ID --file role.md"},
	"roles preview":            {"--file role.md | --markdown role.md", "Compile Markdown into role steps without saving or changing hosts. Exits nonzero on validation errors.", inputHelp + "  --markdown FILE  Explicit Markdown input; - reads stdin\n", "korta roles preview --file role.md"},
	"roles plan":               {"ID [--destroy]", "Show what the role would change without changing hosts. Waits by default; --wait=false returns the operation immediately.", "  --destroy  Plan removing what the role created in AWS instead\n", "korta roles plan role_ID"},
	"roles run":                {"ID [--approve] [--confirm-commands]", "Plan the role, show the plan, then apply it once you confirm (or with --approve). When the manager requires a second approver, the plan waits for them.", "  --approve          Apply without a confirmation prompt\n  --confirm-commands Confirm review of custom commands\n", "korta roles run role_ID"},
	"roles destroy":            {"ID --confirm ROLE_NAME [--approve]", "Plan removing what the role's AWS section created (its instances, security group and key pair), show the plan, then destroy them once you confirm. With four-eyes approval, the plan waits for a second person.", "  --confirm NAME     The role's name, to confirm terminating its instances\n  --approve          Destroy without a confirmation prompt\n", "korta roles destroy role_ID --confirm web"},
	"roles apply":              {"ID --approve [--plan PLAN_ID]", "Apply a reviewed role plan. Defaults to the role's current plan; the server rejects stale or expired plans.", "  --approve          Explicitly approve applying the plan\n  --plan PLAN_ID     Reviewed plan ID (default: current plan)\n  --confirm-commands Confirm review of custom commands\n  --confirm NAME     The role's name, to approve a destroy plan\n", "korta roles apply role_ID --approve --plan plan_ID --wait"},
	"keys create":              {"[NAME] --private-key FILE", "Import an SSH private key into the manager vault. Passphrase-protected keys can be supplied as JSON with name, privateKey and passphrase.", inputHelp + "  --private-key FILE  SSH private key file\n  --name NAME         Alternative to positional NAME\n", "korta keys create production --private-key ~/.ssh/id_ed25519"},
	"secrets list":             {"", "List the secrets in the manager's vault and the roles that use them. Values are never shown.", "", "korta secrets list"},
	"secrets set":              {"NAME [--value-file FILE]", "Create or rotate a secret in the manager's vault. Roles use it as {{ secret.NAME }}. The value is read at a hidden prompt, from --value-file, or from stdin, never from arguments. Rotating invalidates pending plans that use it.", "  --value-file FILE  Read the value from a file; - reads stdin\n", "korta secrets set db_password --value-file db_password.txt"},
	"secrets delete":           {"NAME", "Delete a secret. Refused while a role uses it.", "", "korta secrets delete db_password"},
	"operations wait":          {"ID", "Wait for an operation to finish and show its steps. Failed operations exit nonzero.", "", "korta operations wait op_ID --timeout 30m"},
	"assistant status":         {"", "Show whether the role assistant is enabled and which model it uses.", "", "korta assistant status"},
	"assistant start":          {"[--role ROLE_ID]", "Start a chat to draft a new role or revise an existing role.", "  --role ROLE_ID  Existing role to revise\n" + inputHelp, "korta assistant start --role role_ID"},
	"assistant send":           {"CHAT_ID --text TEXT", "Send instructions to a role drafting chat.", "  --text TEXT  Instructions for the assistant\n" + inputHelp, "korta assistant send chat_ID --text 'Install nginx on staging hosts'"},
	"assistant save":           {"CHAT_ID", "Save the assistant's draft as a role. Plan and approve it separately before applying.", "", "korta assistant save chat_ID"},
	"login":                    {"[--server URL] [--token-file FILE]", "Verify and save manager credentials. Prompts for a hidden token if none is supplied. Saved credentials are restricted to their manager URL.", "", "korta login --server http://127.0.0.1:8080 --token-file data/admin-token"},
	"logout":                   {"", "Remove the locally saved admin token. Does not revoke tokens or other clients' sessions.", "", "korta logout"},
	"health":                   {"", "Check the manager's health endpoint.", "", "korta health"},
	"session":                  {"", "Verify authentication and inspect the manager session.", "", "korta session"},
	"types":                    {"", "List deployment types supported by the manager.", "", "korta types"},
	"ca":                       {"", "Read the manager's TLS CA certificate.", "", "korta ca --json"},
	"audit":                    {"[--target ID]", "Read audit events, optionally filtered by target.", "  --target ID  Filter events by target ID\n", "korta audit --target ins_ID"},
	"provision":                {"--file provision.json", "Register a host and create its deployment in one operation.", inputHelp, "korta provision --file provision.json --wait"},
	"api":                      {"METHOD /api/PATH [--data JSON]", "Call an authenticated API endpoint directly. Paths may include query strings.", inputHelp, "korta api GET /api/instances"},
	"version":                  {"", "Print the CLI build version.", "", "korta version"},
	"plan":                     {"ROLE.md [-i hosts.md] [--limit SELECTOR] [--var NAME=VALUE]", "Plan a Markdown role against inventory hosts over SSH without a manager or changing hosts. The role is compiled for each host with its variables. No default timeout.", localHelpFlags + varHelpFlags, "korta plan site.md -i hosts.md --limit staging"},
	"apply":                    {"ROLE.md [-i hosts.md] [--limit SELECTOR] [--var NAME=VALUE]", "Plan, review and apply a Markdown role over SSH without a manager. Asks for confirmation unless --yes is supplied. No default timeout.", localHelpFlags + varHelpFlags + "  --yes                 Apply without a confirmation prompt\n  --confirm-commands    Confirm review of custom scripts and check commands\n  --batch-size N        Hosts per batch\n  --continue-on-failure Continue after a failed batch\n", "korta apply site.md -i hosts.md --limit staging --var domain=staging.example.com"},
	"inventory":                {"[-i hosts.md] [--limit SELECTOR]", "List selected hosts from a Markdown inventory, with their SSH keys and variables, without a manager.", localHelpFlags, "korta inventory -i hosts.md"},
}

func detailFor(group, action string) commandHelp {
	path := group + " " + action
	if d, ok := commandDetails[path]; ok {
		return d
	}
	d := commandHelp{usage: "ID", summary: action + " " + group + ".", example: "korta " + path + " ID"}
	switch action {
	case "list":
		d.usage = ""
		d.summary = "List " + group + "."
		d.example = "korta " + path
	case "get":
		d.summary = "Show details for one resource."
	case "delete":
		d.summary = "Delete the resource, subject to the manager's dependency checks."
	case "apply":
		d.summary = "Apply the deployment's current spec."
	case "restart":
		d.summary = "Restart the application deployment."
	case "status":
		d.summary = "Check deployment status. Waits by default; use --wait=false to return immediately."
	case "backups":
		d.summary = "List database backups. Waits by default; use --wait=false to return immediately."
	}
	return d
}

func writeCommandHelp(out io.Writer, args []string) error {
	if len(args) == 0 {
		_, err := io.WriteString(out, help)
		return err
	}
	group := args[0]
	if group == "ssh-keys" {
		group = "keys"
	}
	actions, isGroup := commands[group]
	if isGroup && len(args) == 1 {
		var b strings.Builder
		fmt.Fprintf(&b, "Manage %s.\n\nUsage: korta %s COMMAND [flags]\n\nCommands:\n", group, group)
		w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
		for _, action := range actions {
			d := detailFor(group, action)
			fmt.Fprintf(w, "  %s %s\t%s\n", action, d.usage, firstSentence(d.summary))
		}
		_ = w.Flush()
		fmt.Fprintf(&b, "\nUse korta %s COMMAND --help for options and examples.\n\nManager flags:\n%s\nOutput flags:\n%s", group, managerHelpFlags, outputHelpFlags)
		_, err := io.WriteString(out, b.String())
		return err
	}
	path := group
	var d commandHelp
	if isGroup {
		found := false
		for _, action := range actions {
			if action == args[1] {
				found = true
				break
			}
		}
		if !found {
			return unknownCommand(args)
		}
		path += " " + args[1]
		d = detailFor(group, args[1])
	} else {
		var ok bool
		d, ok = commandDetails[group]
		if !ok {
			return unknownCommand(args)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nUsage: korta %s %s\n", d.summary, path, d.usage)
	if d.flags != "" {
		fmt.Fprintf(&b, "\nOptions:\n%s", d.flags)
	}
	offline := group == "plan" || group == "apply" || group == "inventory" || group == "version"
	if !offline {
		fmt.Fprintf(&b, "\nManager flags:\n%s", managerHelpFlags)
		if showWaitFlag(group, args) {
			fmt.Fprintln(&b, "  --wait             Wait for an operation; --wait=false returns immediately")
		}
	}
	if group != "version" {
		fmt.Fprintf(&b, "\nOutput flags:\n%s", outputHelpFlags)
	} else {
		fmt.Fprintln(&b, "\n  --help, -h  Show help for this command")
	}
	fmt.Fprintf(&b, "\nExample:\n  %s\n", d.example)
	_, err := io.WriteString(out, b.String())
	return err
}

func showWaitFlag(group string, args []string) bool {
	if group == "provision" || group == "api" {
		return true
	}
	if len(args) < 2 {
		return false
	}
	switch group {
	case "instances":
		return args[1] == "create" || args[1] == "update" || args[1] == "check" || args[1] == "trust-host-key"
	case "deployments":
		return args[1] != "get" && args[1] != "list" && args[1] != "delete" && args[1] != "connection"
	case "roles":
		return args[1] == "plan" || args[1] == "apply"
	case "operations":
		return args[1] == "wait"
	}
	return false
}

// firstSentence keeps group overviews to one line per command; each
// command's own help has the full text.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
