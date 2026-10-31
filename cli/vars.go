package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nexusrun/korta/inventory"
	"github.com/nexusrun/korta/roles"
)

// localRole is a role file used as a template: it is compiled separately
// for each host once the host's facts are known.
type localRole struct {
	name     string
	path     string
	markdown string            // the template; rendered values are never kept
	files    map[string]string // template files, by path relative to the role
	defaults map[string]string
	cliVars  map[string]string
	secrets  map[string]string // {{ secret.NAME }} values from KORTA_SECRET_NAME
	rollout  roles.Rollout

	mu       sync.Mutex
	compiled map[string]roles.Role // by host name
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// loadRole reads the role file and checks what it can before connecting.
func (c *client) loadRole(path string) (*localRole, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	aws, err := roles.ParseAWS(string(b))
	if err != nil {
		return nil, err
	}
	if aws != nil {
		return nil, fmt.Errorf("AWS provisioning requires a Korta Enterprise manager; use korta roles create --file ROLE.md --name NAME, then roles plan and roles apply --approve")
	}
	name := c.opts.values["name"]
	if name == "" {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		name = strings.Trim(nonName.ReplaceAllString(strings.ToLower(base), "-"), "-")
		if len(name) > 63 {
			name = strings.Trim(name[:63], "-")
		}
	}
	l := &localRole{name: firstOf(name, "role"), path: path, markdown: string(b), compiled: map[string]roles.Role{}}
	if l.files, err = roleFiles(l.markdown, filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v := c.opts.values["batch-size"]; v != "" {
		if l.rollout.BatchSize, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("--batch-size must be 1-100")
		}
	}
	l.rollout.ContinueOnFailure = c.opts.yes("continue-on-failure")
	if l.defaults, err = roles.Variables(l.markdown); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.cliVars, err = c.cliVars(); err != nil {
		return nil, err
	}
	l.secrets = map[string]string{}
	for _, name := range roles.SecretRefs(l.markdown, l.files) {
		if v := os.Getenv(roles.SecretEnv(name)); v != "" {
			l.secrets[roles.SecretPrefix+name] = v
		}
	}
	refs, err := roles.References(l.markdown)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, content := range l.files {
		more, err := roles.References(content)
		if err != nil {
			return l, nil // a raw file; its step reports any mistake per host
		}
		refs = append(refs, more...)
	}
	// When no value depends on a host, compile now so mistakes show before
	// connecting to anything.
	for _, r := range refs {
		if _, ok := l.cliVars[r]; !ok {
			if _, ok := l.defaults[r]; !ok {
				return l, nil
			}
		}
	}
	if _, err := l.compile(map[string]string{}); err != nil {
		return nil, err
	}
	return l, nil
}

// cliVars reads repeated --var NAME=VALUE flags.
func (c *client) cliVars() (map[string]string, error) {
	vars := map[string]string{}
	for _, kv := range strings.Split(c.opts.values["var"], "\n") {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`).MatchString(k) {
			return nil, fmt.Errorf("--var takes NAME=VALUE, such as --var domain=example.com")
		}
		vars[k] = v
	}
	return vars, nil
}

// compile renders the role with host values over the role's defaults,
// with --var winning over both.
func (l *localRole) compile(hostVars map[string]string) (roles.Role, error) {
	vars := map[string]string{}
	for _, layer := range []map[string]string{l.defaults, hostVars, l.cliVars} {
		for k, v := range layer {
			if strings.HasPrefix(k, roles.SecretPrefix) {
				return roles.Role{}, fmt.Errorf("%s is a secret: set %s in the environment instead", k, roles.SecretEnv(k))
			}
			expanded, err := expandEnv(k, v)
			if err != nil {
				return roles.Role{}, err
			}
			vars[k] = expanded
		}
	}
	for k, v := range l.secrets {
		vars[k] = v
	}
	r := roles.Role{Name: l.name, Markdown: l.markdown, Files: l.files, Targets: roles.Targets{InstanceIDs: []string{"inventory"}}, Rollout: l.rollout}
	if err := r.Compile(vars); err != nil {
		return roles.Role{}, fmt.Errorf("%s: %w", l.path, l.redact(err))
	}
	return r, nil
}

// secretValues are the values to blank out of anything printed or logged.
func (l *localRole) secretValues() []string {
	out := []string{}
	for _, v := range l.secrets {
		out = append(out, v)
	}
	return out
}

func (l *localRole) redact(err error) error {
	return fmt.Errorf("%s", roles.Redact(err.Error(), l.secretValues()))
}

// prepare compiles the role for one host once its facts are known.
func (l *localRole) prepare(h inventory.Host) func(roles.Host) (roles.Role, error) {
	return func(os roles.Host) (roles.Role, error) {
		vars := map[string]string{}
		for k, v := range h.Labels {
			vars[k] = v
		}
		for k, v := range roles.Facts(h.Name, h.Address, os) {
			vars[k] = v
		}
		r, err := l.compile(vars)
		if err != nil {
			return r, err
		}
		l.mu.Lock()
		l.compiled[h.Name] = r
		l.mu.Unlock()
		return r, nil
	}
}

// hash identifies the template, for plans and run logs.
func (l *localRole) hash() string {
	return roles.Role{Markdown: l.markdown, Files: l.files}.Hash()
}

// review gathers what needs care across every host's compiled role.
func (l *localRole) review() (risks []string, commands bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := map[string]bool{}
	for _, r := range l.compiled {
		commands = commands || r.HasCommand()
		for _, risk := range r.Risky() {
			if !seen[risk] {
				seen[risk] = true
				risks = append(risks, risk)
			}
		}
	}
	sort.Strings(risks)
	return risks, commands
}

// roleFiles reads the template files a role names with "from", relative to
// the role file's folder.
func roleFiles(markdown, dir string) (map[string]string, error) {
	sources, err := roles.Sources(markdown)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, src := range sources {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(src)))
		if err != nil {
			return nil, fmt.Errorf("template file %s: %w", src, err)
		}
		files[src] = string(b)
	}
	return files, nil
}

// expandEnv fills ${NAME} in a value from the environment of the machine
// running korta, such as secrets in CI.
func expandEnv(name, value string) (string, error) {
	var err error
	out := envRef.ReplaceAllStringFunc(value, func(ref string) string {
		env := ref[2 : len(ref)-1]
		v, ok := os.LookupEnv(env)
		if (!ok || v == "") && err == nil {
			err = fmt.Errorf("the variable %s uses ${%s}, which is not set", name, env)
		}
		return v
	})
	return out, err
}
