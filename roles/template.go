package roles

import (
	"fmt"
	"regexp"
	"strings"
)

// A role is a template: {{ name }} anywhere in it is replaced with the
// variable's value before the role is compiled, separately for each host.
// Values come from the role's # Variables section, the inventory, the
// command line and host facts such as {{ host.name }} and {{ os.distro }}.
// Rendering is plain substitution: no expressions, loops or conditions.
// Code blocks marked raw are copied exactly.

var (
	refRe     = regexp.MustCompile(`\{\{(.*?)\}\}`)
	varNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	varLineRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]{0,63})\s*(?:=|:)\s*(.*)$`)
)

// Variables reads the defaults in the role's # Variables section.
func Variables(markdown string) (map[string]string, error) {
	items, err := scanMarkdown(markdown)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for _, it := range items {
		if it.kind != "vars" {
			continue
		}
		if it.code != nil || len(it.extra) > 0 {
			return nil, it.errorf("write each variable as one bullet, such as - domain = example.com")
		}
		m := varLineRe.FindStringSubmatch(strings.TrimSpace(it.text))
		if m == nil {
			return nil, it.errorf("write variables as - name = value, with a name of letters, digits and _")
		}
		value := strings.TrimSpace(m[2])
		if len(value) >= 2 && (value[0] == '`' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if strings.Contains(value, "{{") {
			return nil, it.errorf("a variable's value cannot use other variables")
		}
		if _, dup := vars[m[1]]; dup {
			return nil, it.errorf("%s is set twice", m[1])
		}
		vars[m[1]] = value
	}
	return vars, nil
}

// References lists the variables a role uses, in order of first use.
func References(markdown string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	_, err := render(markdown, func(name string, line int) (string, error) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		return "", nil
	})
	return out, err
}

// SecretPrefix marks secrets: {{ secret.db_password }} comes from the
// manager's vault, or offline from KORTA_SECRET_DB_PASSWORD.
const SecretPrefix = "secret."

// SecretPlaceholder stands in for secrets when a role is checked without
// them, such as when it is saved.
const SecretPlaceholder = "SECRET"

// Render replaces every {{ name }} with its value. A missing variable is an
// error with its line number, never an empty value. Values must be single
// lines, so they cannot change the Markdown's structure.
func Render(markdown string, vars map[string]string) (string, error) {
	return renderValues(markdown, vars, false)
}

// RenderFile renders a template file, where values may span lines, such as
// a TLS key from the vault.
func RenderFile(content string, vars map[string]string) (string, error) {
	return renderValues(content, vars, true)
}

func renderValues(text string, vars map[string]string, multiline bool) (string, error) {
	return render(text, func(name string, line int) (string, error) {
		v, ok := vars[name]
		switch {
		case ok:
		case strings.HasPrefix(name, "host.") || strings.HasPrefix(name, "os."):
			return "", fmt.Errorf("line %d: {{ %s }} is only known when the role runs on a host", line, name)
		case strings.HasPrefix(name, SecretPrefix):
			return "", fmt.Errorf("line %d: the secret %s is not available; on a manager, set it with korta secrets set %s; offline, set %s", line, strings.TrimPrefix(name, SecretPrefix), strings.TrimPrefix(name, SecretPrefix), SecretEnv(name))
		default:
			return "", fmt.Errorf("line %d: {{ %s }} is not set; give it a default in # Variables, or a value per host in the inventory, an instance label or --var", line, name)
		}
		if !multiline && strings.ContainsAny(v, "\n\r") {
			return "", fmt.Errorf("line %d: the value of %s spans lines; use it in a template file (from FILE)", line, name)
		}
		return v, nil
	})
}

// SecretEnv is the environment variable that holds a secret offline.
func SecretEnv(name string) string {
	return "KORTA_SECRET_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimPrefix(name, SecretPrefix)))
}

// SecretRefs lists the secrets a role uses, by name without the prefix.
func SecretRefs(markdown string, files map[string]string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(text string) {
		refs, _ := References(text)
		for _, r := range refs {
			if name, ok := strings.CutPrefix(r, SecretPrefix); ok && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	add(markdown)
	for _, f := range files {
		add(f)
	}
	return out
}

// Redact replaces secret values in text, for step output and errors.
func Redact(text string, secrets []string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, "[secret]")
		}
	}
	return text
}

// RedactResult removes secret values from a host's step details and errors.
func RedactResult(h HostResult, secrets []string) HostResult {
	if len(secrets) == 0 {
		return h
	}
	h.Error = Redact(h.Error, secrets)
	steps := make([]StepResult, len(h.Steps))
	for i, s := range h.Steps {
		s.Detail = Redact(s.Detail, secrets)
		steps[i] = s
	}
	h.Steps = steps
	return h
}

func render(markdown string, value func(name string, line int) (string, error)) (string, error) {
	lines := strings.Split(markdown, "\n")
	fence, raw := "", false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if fence != "" {
			if strings.HasPrefix(t, fence) && strings.Trim(t, fence[:1]) == "" {
				fence, raw = "", false
				continue
			}
			if raw {
				continue
			}
		} else if m := fenceRe.FindString(t); m != "" {
			fence = m
			for _, w := range strings.Fields(strings.TrimPrefix(t, m)) {
				raw = raw || strings.EqualFold(w, "raw")
			}
			continue
		}
		var err error
		lines[i] = refRe.ReplaceAllStringFunc(l, func(ref string) string {
			if err != nil {
				return ref
			}
			name := strings.TrimSpace(ref[2 : len(ref)-2])
			if !varNameRe.MatchString(name) {
				err = fmt.Errorf("line %d: %s: only plain variables such as {{ domain }} are supported; mark the code block raw to keep it as written", i+1, ref)
				return ref
			}
			v, e := value(name, i+1)
			err = e
			return v
		})
		if err != nil {
			return "", err
		}
	}
	return strings.Join(lines, "\n"), nil
}

// Sources lists the template files a role's Files bullets name with "from",
// which are sent along with the role.
func Sources(markdown string) ([]string, error) {
	items, err := scanMarkdown(markdown)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		if it.kind != "file" {
			continue
		}
		toks := words(strings.Join(append([]string{it.text}, it.extra...), " "))
		for i := 0; i+1 < len(toks); i++ {
			if !strings.EqualFold(toks[i], "from") {
				continue
			}
			src := toks[i+1]
			if strings.Contains(src, "{{") {
				return nil, it.errorf("template file names cannot use variables; use variables inside the file")
			}
			if err := checkSource(src); err != nil {
				return nil, it.errorf("%v", err)
			}
			if !seen[src] {
				seen[src] = true
				out = append(out, src)
			}
		}
	}
	return out, nil
}

// SampleFacts stand in for host facts when a role is checked without a
// host, such as when it is saved.
func SampleFacts() map[string]string {
	return map[string]string{
		"host.name": "example-host", "host.address": "192.0.2.10",
		"os.distro": "ubuntu", "os.version": "24.04", "os.family": "apt", "os.arch": "amd64",
	}
}

// Facts are the built-in variables for a host.
func Facts(name, address string, h Host) map[string]string {
	return map[string]string{
		"host.name": name, "host.address": address,
		"os.distro": h.Distro, "os.version": h.Version, "os.family": h.Family, "os.arch": h.Arch,
	}
}
