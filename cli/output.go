package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// print writes a response: JSON with --json or --output json, otherwise a
// readable view for lists and operations and indented JSON for the rest.
func (c *client) print(b []byte) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	if c.format() == "table" {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var v any
		if d.Decode(&v) == nil && c.render(v) {
			return nil
		}
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		return err
	}
	_, err := fmt.Fprintln(c.out, pretty.String())
	return err
}

func (c *client) format() string {
	if c.opts.yes("json") {
		return "json"
	}
	return firstOf(c.opts.values["output"], "table")
}

// render prints v for people and reports whether it knew how.
func (c *client) render(v any) bool {
	a := c.opts.args
	if rows, ok := v.([]any); ok && (a[0] == "audit" || (len(a) == 2 && a[1] == "list")) {
		c.list(a[0], rows)
		return true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if len(a) == 3 && a[0] == "secrets" && a[1] == "set" {
		fmt.Fprintf(c.out, "Saved %s. Roles use it as {{ secret.%s }}", str(m, "name"), str(m, "name"))
		if used := str(m, "usedBy"); used != "" {
			fmt.Fprintf(c.out, "; plan %s again before approving", used)
		}
		fmt.Fprintln(c.out, ".")
		return true
	}
	if isOperation(m) {
		c.operation(m)
		return true
	}
	if op, ok := m["operation"].(map[string]any); ok && isOperation(op) {
		for _, kind := range []string{"instance", "deployment"} {
			if r, ok := m[kind].(map[string]any); ok {
				fmt.Fprintf(c.out, "Created %s %s (%s).\n", kind, str(r, "name"), str(r, "id"))
			}
		}
		c.operation(op)
		return true
	}
	return false
}

type column struct {
	title string
	value func(map[string]any) string
}

func field(path string) func(map[string]any) string {
	return func(m map[string]any) string { return str(m, path) }
}

var listColumns = map[string][]column{
	"instances": {{"ID", field("id")}, {"NAME", field("name")}, {"ADDRESS", func(m map[string]any) string {
		addr := str(m, "ssh.user") + "@" + str(m, "ssh.host")
		if p := str(m, "ssh.port"); p != "" && p != "22" && p != "0" {
			addr += ":" + p
		}
		return addr
	}}, {"OS", func(m map[string]any) string {
		return strings.TrimSpace(str(m, "os.distro") + " " + str(m, "os.version") + " " + str(m, "os.arch"))
	}}, {"STATUS", field("status")}, {"LABELS", func(m map[string]any) string { return pairs(m["labels"]) }}},
	"deployments": {{"ID", field("id")}, {"NAME", field("name")}, {"TYPE", field("type")}, {"INSTANCES", func(m map[string]any) string {
		return fmt.Sprint(len(asList(m["instanceIDs"])))
	}}, {"REVISION", func(m map[string]any) string {
		return str(m, "appliedRevision") + "/" + str(m, "revision")
	}}, {"STATUS", field("status")}},
	"roles": {{"ID", field("id")}, {"NAME", field("name")}, {"VERSION", func(m map[string]any) string { return "v" + str(m, "version") }}, {"INSTANCES", func(m map[string]any) string {
		return fmt.Sprint(len(asList(m["targetNames"])))
	}}, {"RISKS", func(m map[string]any) string { return fmt.Sprint(len(asList(m["risks"]))) }}, {"PLAN", func(m map[string]any) string {
		if p, ok := m["plan"].(map[string]any); ok {
			return fmt.Sprintf("%s (%s changes)", str(p, "operationID"), str(p, "changes"))
		}
		return "none"
	}}},
	"keys":       {{"ID", field("id")}, {"NAME", field("name")}, {"KIND", field("kind")}, {"FINGERPRINT", field("fingerprint")}},
	"secrets":    {{"NAME", field("name")}, {"UPDATED", func(m map[string]any) string { return when(str(m, "updatedAt")) }}, {"USED BY", field("usedBy")}},
	"operations": {{"ID", field("id")}, {"TITLE", field("title")}, {"STATUS", field("status")}, {"STARTED", func(m map[string]any) string { return when(str(m, "startedAt")) }}},
	"audit":      {{"TIME", func(m map[string]any) string { return when(str(m, "time")) }}, {"ACTION", field("action")}, {"TARGET", field("targetID")}, {"DETAIL", field("detail")}},
}

var emptyLists = map[string]string{
	"instances":   "No instances. Register one with: korta instances create NAME --host HOST --user USER --key KEY_ID",
	"deployments": "No deployments. Create one with: korta deployments create NAME --type TYPE --instance ID",
	"roles":       "No roles. Create one with: korta roles create --file role.md --name NAME --label KEY=VALUE",
	"keys":        "No SSH keys. Add one with: korta keys create NAME --private-key FILE",
	"secrets":     "No secrets. Add one with: korta secrets set NAME (the value is read at a hidden prompt or from stdin)",
	"operations":  "No operations yet.",
	"audit":       "No audit events.",
}

func (c *client) list(resource string, rows []any) {
	if resource == "ssh-keys" {
		resource = "keys"
	}
	if len(rows) == 0 {
		fmt.Fprintln(c.out, firstOf(emptyLists[resource], "Nothing found."))
		return
	}
	cols := listColumns[resource]
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	titles := []string{}
	for _, col := range cols {
		titles = append(titles, col.title)
	}
	fmt.Fprintln(w, strings.Join(titles, "\t"))
	for _, row := range rows {
		m, _ := row.(map[string]any)
		cells := []string{}
		for _, col := range cols {
			cells = append(cells, firstOf(clean(col.value(m)), "-"))
		}
		fmt.Fprintln(w, strings.Join(cells, "\t"))
	}
	w.Flush()
}

func isOperation(m map[string]any) bool {
	id, _ := m["id"].(string)
	_, hasStatus := m["status"]
	return strings.HasPrefix(id, "op_") && hasStatus
}

// operation prints an operation's outcome. After --wait the steps were
// already reported on stderr, so only the result follows.
func (c *client) operation(op map[string]any) {
	status := str(op, "status")
	if !c.waited {
		fmt.Fprintf(c.out, "%s: %s (%s)\n", str(op, "title"), status, str(op, "id"))
		if status == "running" {
			fmt.Fprintf(c.out, "Follow it with: korta operations wait %s\n", str(op, "id"))
			return
		}
		for _, s := range asList(op["steps"]) {
			step, _ := s.(map[string]any)
			fmt.Fprintf(c.out, "  %-9s %s\n", str(step, "status"), clean(str(step, "name")))
		}
	}
	result, _ := op["result"].(map[string]any)
	switch {
	case result == nil:
	case result["kind"] == "plan" || result["kind"] == "apply":
		c.roleRun(result)
	case asList(result["hosts"]) != nil:
		c.hostResults(asList(result["hosts"]))
	case asList(result["backups"]) != nil:
		c.table(asList(result["backups"]))
	default:
		c.keyValues(result)
	}
	if status == "failed" && str(op, "detail") != "" {
		fmt.Fprintf(c.out, "Error: %s\n", clean(str(op, "detail")))
	}
}

// roleRun prints a role plan or apply like the web console does.
func (c *client) roleRun(run map[string]any) {
	// A local apply shows its plan as "apply-preview": no hints, the
	// confirmation prompt follows.
	preview := run["kind"] == "apply-preview"
	plan := run["kind"] == "plan" || preview
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "INSTANCE\tSTEP\tRESULT\tDETAIL")
	hosts := asList(run["hosts"])
	for _, h := range hosts {
		host, _ := h.(map[string]any)
		steps := asList(host["steps"])
		if len(steps) == 0 {
			fmt.Fprintf(w, "%s\t-\t%s\t%s\n", clean(str(host, "instance")), str(host, "status"), clean(firstLine(str(host, "error"))))
			continue
		}
		for i, s := range steps {
			step, _ := s.(map[string]any)
			name := ""
			if i == 0 {
				name = clean(str(host, "instance"))
			}
			result := str(step, "status")
			if plan && result == "changed" {
				result = "will change"
			}
			fmt.Fprintf(w, "%s\t%s. %s\t%s\t%s\n", name, str(step, "step"), clean(str(step, "name")), result, clean(firstLine(str(step, "detail"))))
		}
	}
	w.Flush()
	changes, failed := str(run, "changes"), str(run, "failed")
	fmt.Fprintf(c.out, "\n%s on %s", count(changes, "change"), count(fmt.Sprint(len(hosts)), "instance"))
	if failed != "" && failed != "0" {
		fmt.Fprintf(c.out, ", failed on %s", failed)
	}
	fmt.Fprintln(c.out, ".")
	switch {
	case !plan || preview || (failed != "" && failed != "0"):
	case changes == "0":
		fmt.Fprintln(c.out, "Nothing to change: the instances already match the role.")
	case str(run, "applyHint") != "":
		fmt.Fprintln(c.out, str(run, "applyHint"))
	default:
		fmt.Fprintf(c.out, "Review it, then apply exactly this plan with: korta roles apply %s --approve\n", str(run, "roleID"))
	}
}

// hostResults prints deployment action results: logs as plain text, the
// rest as a table.
func (c *client) hostResults(hosts []any) {
	for _, h := range hosts {
		if host, _ := h.(map[string]any); str(host, "output") != "" && strings.Contains(str(host, "output"), "\n") {
			for _, h := range hosts {
				host, _ := h.(map[string]any)
				fmt.Fprintf(c.out, "== %s\n", clean(str(host, "instance")))
				if e := str(host, "error"); e != "" {
					fmt.Fprintf(c.out, "error: %s\n", clean(e))
				}
				io.WriteString(c.out, strings.TrimRight(terminalSafe(str(host, "output")), "\n")+"\n")
			}
			return
		}
	}
	c.table(hosts)
}

// table prints objects with their scalar fields as columns, the most
// useful ones first.
func (c *client) table(rows []any) {
	order := []string{"instance", "name", "id", "state", "status", "release", "since", "time", "bytes", "label", "type", "output", "error"}
	seen := map[string]bool{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		for k, v := range m {
			if _, nested := v.(map[string]any); !nested {
				seen[k] = true
			}
		}
	}
	cols := []string{}
	for _, k := range order {
		if seen[k] {
			cols = append(cols, k)
			delete(seen, k)
		}
	}
	rest := keys(seen)
	sort.Strings(rest)
	cols = append(cols, rest...)
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, strings.ToUpper(strings.Join(cols, "\t")))
	for _, r := range rows {
		m, _ := r.(map[string]any)
		cells := []string{}
		for _, k := range cols {
			cells = append(cells, firstOf(clean(firstLine(str(m, k))), "-"))
		}
		fmt.Fprintln(w, strings.Join(cells, "\t"))
	}
	w.Flush()
}

func (c *client) keyValues(m map[string]any) {
	ks := []string{}
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	for _, k := range ks {
		if v := clean(str(m, k)); v != "" {
			fmt.Fprintf(w, "%s\t%s\n", k, v)
		}
	}
	w.Flush()
}

// str reads a dotted path such as "ssh.host" as text.
func str(m map[string]any, path string) string {
	var v any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = obj[part]
	}
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number, bool:
		return fmt.Sprint(x)
	case []any:
		parts := []string{}
		for _, e := range x {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func count(n, noun string) string {
	if n == "1" {
		return n + " " + noun
	}
	return n + " " + noun + "s"
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func pairs(v any) string {
	m, _ := v.(map[string]any)
	out := []string{}
	for k, val := range m {
		out = append(out, fmt.Sprintf("%s=%v", k, val))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func when(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04")
}

// clean keeps one line of server text from breaking table layout or the
// terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return -1
		}
		return r
	}, s)
}

// terminalSafe removes control characters other than newlines from text,
// such as logs, printed as is.
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}
