package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// commands lists each resource's actions, for routing errors and suggestions.
var commands = map[string][]string{
	"disk":        {"inspect"},
	"network":     {"inspect"},
	"instances":   {"list", "get", "create", "update", "delete", "check", "trust-host-key", "console"},
	"deployments": {"list", "get", "create", "update", "delete", "apply", "status", "logs", "restart", "rollback", "backup", "backups", "restore", "action", "connection"},
	"roles":       {"list", "get", "create", "update", "delete", "preview", "plan", "apply", "run", "destroy"},
	"keys":        {"list", "create", "delete"},
	"secrets":     {"list", "set", "delete"},
	"operations":  {"list", "get", "wait"},
	"assistant":   {"status", "start", "send", "save"},
}

// topLevel are commands without a subcommand.
var topLevel = []string{"login", "logout", "health", "types", "ca", "session", "audit", "provision", "api", "version", "plan", "apply", "inventory", "copy"}

// waitByDefault are commands whose result is only useful once the operation
// finishes. --wait=false turns waiting off.
var waitByDefault = map[string]bool{
	"deployments status": true, "deployments logs": true, "deployments backups": true, "roles plan": true, "roles run": true, "roles destroy": true,
}

// route maps the parsed command to an API request. The method CONSOLE opens
// an interactive console instead of a request.
func (c *client) route() (method, path string, body []byte, err error) {
	a := c.opts.args
	if body, err = c.payload(); err != nil {
		return "", "", nil, err
	}
	r := &request{c: c, args: a, body: body}
	switch {
	case len(a) == 1:
		r.topLevel()
	case a[0] == "api":
		r.raw()
	case a[0] == "assistant":
		r.assistant()
	case a[0] == "secrets":
		r.secrets()
	default:
		r.resource()
	}
	if r.err == nil && r.method == "" {
		r.err = unknownCommand(a)
	}
	return r.method, r.path, r.body, r.err
}

// request accumulates one routed command.
type request struct {
	c            *client
	args         []string
	method, path string
	body         []byte
	err          error
}

func (r *request) to(method, path string) { r.method, r.path = method, path }

func (r *request) fail(format string, args ...any) { r.err = fmt.Errorf(format, args...) }

func (r *request) object(v any) { r.body, _ = json.Marshal(v) }

func (r *request) topLevel() {
	o := r.c.opts
	switch r.args[0] {
	case "health", "types", "ca", "session":
		r.to("GET", "/api/"+r.args[0])
	case "audit":
		q := url.Values{}
		if v := o.values["target"]; v != "" {
			q.Set("target", v)
		}
		r.to("GET", "/api/audit?"+q.Encode())
	case "provision":
		if r.body == nil {
			r.fail("provision needs a request: --file FILE or --data JSON")
			return
		}
		r.to("POST", "/api/provision")
	}
}

func (r *request) raw() {
	if len(r.args) != 3 {
		r.fail("usage: korta api METHOD /api/PATH")
		return
	}
	p := r.args[2]
	if !strings.HasPrefix(p, "/api/") || strings.Contains(p, "..") || strings.ContainsAny(p, "#\\") {
		r.fail("the API path must start with /api/ and contain no ..")
		return
	}
	r.to(strings.ToUpper(r.args[1]), p)
}

func (r *request) assistant() {
	a, o := r.args, r.c.opts
	switch {
	case len(a) == 2 && a[1] == "status":
		r.to("GET", "/api/assistant")
	case len(a) == 2 && a[1] == "start":
		if r.body == nil {
			r.object(map[string]string{"roleID": o.values["role"]})
		}
		r.to("POST", "/api/assistant/chats")
	case len(a) == 3 && a[1] == "send":
		if r.body == nil {
			r.object(map[string]string{"text": o.values["text"]})
		}
		r.to("POST", "/api/assistant/chats/"+url.PathEscape(a[2])+"/messages")
	case len(a) == 3 && a[1] == "save":
		r.to("POST", "/api/assistant/chats/"+url.PathEscape(a[2])+"/save")
	}
}

// secrets manages the manager's vault. Values are read from a hidden
// prompt, --value-file or stdin, never from arguments, which shells keep in
// their history.
func (r *request) secrets() {
	a := r.args
	switch {
	case len(a) == 2 && a[1] == "list":
		r.to("GET", "/api/secrets")
	case len(a) == 3 && (a[1] == "set" || a[1] == "delete"):
		if !secretNamePattern.MatchString(a[2]) {
			r.fail("secret names are lowercase letters, digits and _, starting with a letter, such as db_password")
			return
		}
		if a[1] == "delete" {
			r.to("DELETE", "/api/secrets/"+a[2])
			return
		}
		if r.body != nil {
			r.fail("give the value with --value-file FILE, on stdin, or at the prompt, not --data or --file")
			return
		}
		value, err := r.c.secretValue(a[2])
		if err != nil {
			r.err = err
			return
		}
		r.object(map[string]string{"value": value})
		r.to("PUT", "/api/secrets/"+a[2])
	}
}

var secretNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (r *request) resource() {
	a := r.args
	if a[0] == "ssh-keys" {
		a[0] = "keys"
	}
	if _, ok := commands[a[0]]; !ok || len(a) < 2 {
		return
	}
	resource := a[0]
	if resource == "keys" {
		resource = "ssh-keys"
	}
	base := "/api/" + resource
	if len(a) == 2 || (len(a) == 3 && a[1] == "create") {
		r.collection(resource, base)
		return
	}
	id := a[2]
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\?#") {
		r.fail("invalid ID %q", id)
		return
	}
	path := base + "/" + url.PathEscape(id)
	if resource == "deployments" && a[1] == "action" && len(a) == 4 {
		r.to("POST", path+"/actions/"+url.PathEscape(a[3]))
		return
	}
	if len(a) != 3 {
		return
	}
	switch {
	case a[1] == "get" && resource != "ssh-keys":
		r.to("GET", path)
	case a[1] == "delete" && resource != "operations":
		r.to("DELETE", path)
	case resource == "instances":
		r.instance(path)
	case resource == "deployments":
		r.deployment(path)
	case resource == "roles":
		r.role(path)
	case resource == "operations" && a[1] == "wait":
		r.c.opts.values["wait"] = "true"
		r.to("GET", path)
	}
}

// collection handles list, create and preview, which take no ID.
func (r *request) collection(resource, base string) {
	a, o := r.args, r.c.opts
	switch a[1] {
	case "list":
		if len(a) == 2 {
			r.to("GET", base)
		}
	case "create":
		if resource == "operations" {
			return
		}
		name := ""
		if len(a) == 3 {
			name = a[2]
		} else if resource == "instances" || resource == "deployments" {
			name = o.values["name"] // --name instead of the positional NAME
		}
		switch {
		case resource == "ssh-keys" && o.values["private-key"] != "":
			key, err := os.ReadFile(o.values["private-key"])
			if err != nil {
				r.err = err
				return
			}
			r.object(map[string]string{"name": firstOf(name, o.values["name"]), "privateKey": string(key)})
		case resource == "instances" && name != "":
			r.instanceFromFlags(name)
		case resource == "deployments" && name != "":
			r.deploymentFromFlags(name)
		}
		if r.err == nil && r.body == nil {
			r.fail("%s", createUsage[resource])
			return
		}
		r.to("POST", base)
	case "preview":
		if resource != "roles" || len(a) != 2 {
			return
		}
		if r.body == nil {
			r.fail("preview needs role Markdown: --markdown FILE")
			return
		}
		r.to("POST", base+"/preview")
	}
}

var createUsage = map[string]string{
	"instances":   "usage: korta instances create NAME --host HOST --user USER --key KEY_ID, or --file FILE with the JSON request",
	"deployments": "usage: korta deployments create NAME --type TYPE --instance ID [--file SPEC], or --file FILE with the JSON request",
	"roles":       "usage: korta roles create --file role.md --name NAME --label KEY=VALUE, or --file FILE with the JSON request",
	"ssh-keys":    "usage: korta keys create NAME --private-key FILE",
}

func (r *request) instanceFromFlags(name string) {
	o := r.c.opts
	if r.body != nil {
		r.fail("give either flags or --file/--data for instances create, not both")
		return
	}
	if o.values["host"] == "" || o.values["user"] == "" || o.values["key"] == "" {
		r.fail("%s", createUsage["instances"])
		return
	}
	ssh := map[string]any{"host": o.values["host"], "user": o.values["user"], "secretID": o.values["key"]}
	if v := o.values["port"]; v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			r.fail("--port must be 1-65535")
			return
		}
		ssh["port"] = port
	}
	if v := o.values["host-key"]; v != "" {
		ssh["hostKey"] = v
	}
	labels, err := o.labels("label")
	if err != nil {
		r.err = err
		return
	}
	r.object(map[string]any{"name": name, "ssh": ssh, "labels": labels})
}

func (r *request) deploymentFromFlags(name string) {
	o := r.c.opts
	instances := o.list("instance")
	if o.values["type"] == "" || len(instances) == 0 {
		r.fail("%s", createUsage["deployments"])
		return
	}
	// With flags, --file or --data holds the spec alone.
	spec := json.RawMessage("{}")
	if r.body != nil {
		spec = r.body
	}
	r.object(map[string]any{"name": name, "type": o.values["type"], "instanceIDs": instances, "spec": spec})
}

func (r *request) instance(path string) {
	switch r.args[1] {
	case "update":
		if r.body == nil {
			r.fail("update needs the instance as JSON: --file FILE or --data JSON")
			return
		}
		r.to("PUT", path)
	case "check", "trust-host-key":
		r.to("POST", path+"/"+r.args[1])
	case "console":
		r.to("CONSOLE", path+"/console")
	}
}

func (r *request) deployment(path string) {
	o := r.c.opts
	switch action := r.args[1]; action {
	case "update":
		if r.body == nil {
			r.fail("update needs the spec as JSON: --file FILE or --data JSON")
			return
		}
		r.to("PUT", path+"/spec")
	case "apply":
		r.to("POST", path+"/apply")
	case "status", "logs", "restart", "rollback", "backup", "backups", "restore":
		r.to("POST", path+"/actions/"+action)
	case "connection":
		q := url.Values{}
		q.Set("role", o.values["role"])
		q.Set("database", o.values["database"])
		r.to("GET", path+"/connection?"+q.Encode())
	}
}

func (r *request) role(path string) {
	o := r.c.opts
	switch r.args[1] {
	case "update":
		if r.body == nil {
			r.fail("update needs role Markdown or JSON: --file FILE")
			return
		}
		r.to("PUT", path)
	case "plan", "run":
		// run continues with the approval in runRole once the plan is done.
		if o.yes("destroy") {
			r.object(map[string]any{"destroy": true})
		}
		r.to("POST", path+"/plan")
	case "destroy":
		if o.values["confirm"] == "" {
			r.fail("destroying terminates the role's AWS instances; add --confirm ROLE_NAME")
			return
		}
		r.object(map[string]any{"destroy": true})
		r.to("POST", path+"/plan")
	case "apply":
		if !o.yes("approve") {
			r.fail("applying changes hosts; review the plan, then add --approve (custom scripts also need --confirm-commands)")
			return
		}
		// An empty plan ID is resolved to the role's current plan in Run.
		r.object(map[string]any{"planID": o.values["plan"], "approve": true, "confirmCommands": o.yes("confirm-commands"), "confirm": o.values["confirm"]})
		r.to("POST", path+"/apply")
	}
}

func unknownCommand(a []string) error {
	cmd := strings.Join(a, " ")
	if actions, ok := commands[a[0]]; ok {
		if len(a) > 1 {
			if s := closest(a[1], actions); s != "" && s != a[1] {
				return fmt.Errorf("unknown command %q; did you mean %q? (see korta --help)", cmd, a[0]+" "+s)
			}
		}
		return fmt.Errorf("unknown command %q; %s takes: %s", cmd, a[0], strings.Join(actions, ", "))
	}
	all := append([]string{}, topLevel...)
	for r := range commands {
		all = append(all, r)
	}
	if s := closest(a[0], all); s != "" {
		return fmt.Errorf("unknown command %q; did you mean %q? (see korta --help)", cmd, s)
	}
	return fmt.Errorf("unknown command %q (see korta --help)", cmd)
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
