// Package cli implements korta, the command-line client for the manager.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// Version is set at build time with -ldflags "-X github.com/nexusrun/korta/cli.Version=v1.2.3".
var Version = ""

type config struct {
	Server string `json:"server"`
	Token  string `json:"token,omitempty"`
}

type client struct {
	base         string
	token        string
	http         *http.Client
	out, errOut  io.Writer
	in           io.Reader
	opts         options
	roleMarkdown bool
	waited       bool // operation progress was already reported
}

// Run executes one korta command.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if len(o.args) == 0 || o.yes("help") {
		return writeCommandHelp(out, o.args)
	}
	if _, group := commands[o.args[0]]; group && len(o.args) == 1 {
		return writeCommandHelp(out, o.args)
	}
	if o.args[0] == "ssh-keys" && len(o.args) == 1 {
		return writeCommandHelp(out, o.args)
	}
	if f := o.values["output"]; f != "" && f != "json" && f != "table" {
		return fmt.Errorf("--output must be table or json")
	}
	if o.args[0] == "version" {
		fmt.Fprintln(out, "korta", version())
		return nil
	}
	timeout := 10 * time.Minute
	if v := o.values["timeout"]; v != "" {
		if timeout, err = time.ParseDuration(v); err != nil || timeout <= 0 {
			return fmt.Errorf("--timeout must be a positive duration such as 30m")
		}
	}
	switch o.args[0] {
	case "plan", "apply", "inventory":
		// Offline mode needs no manager or credentials.
		c := &client{in: in, out: out, errOut: errOut, opts: o}
		return c.local(ctx)
	}
	p, err := configPath(o)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	c, err := newClient(o, cfg, in, out, errOut)
	if err != nil {
		return err
	}
	switch o.args[0] {
	case "login":
		return c.login(ctx, p)
	case "logout":
		if len(o.args) != 1 {
			return fmt.Errorf("usage: korta logout")
		}
		cfg.Token = ""
		return saveConfig(p, cfg, out)
	}
	method, path, body, err := c.route()
	if err != nil {
		return err
	}
	if err = c.checkTransport(); err != nil {
		return err
	}
	// A console is interactive and has its own idle and session limits on
	// the manager, so --timeout does not apply to it.
	if method == "CONSOLE" {
		return c.console(ctx, path)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	a := o.args
	if c.roleMarkdown && len(a) == 3 && a[0] == "roles" && a[1] == "update" {
		if body, err = c.mergeRoleUpdate(ctx, path, body); err != nil {
			return err
		}
	}
	if len(a) == 3 && a[0] == "roles" && a[1] == "apply" && o.values["plan"] == "" {
		if body, err = c.currentPlan(ctx, a[2], body); err != nil {
			return err
		}
	}
	res, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	if len(a) == 2 && a[0] == "roles" && a[1] == "preview" {
		return c.previewResult(res)
	}
	if len(a) == 3 && a[0] == "secrets" && a[1] == "delete" && c.format() != "json" {
		fmt.Fprintf(c.out, "Deleted %s.\n", a[2])
		return nil
	}
	wait := o.yes("wait")
	if len(a) >= 2 && !o.set("wait") && waitByDefault[a[0]+" "+a[1]] {
		wait = true
	}
	if wait {
		if id := operationID(res); id != "" {
			if res, err = c.wait(ctx, id); err != nil {
				_ = c.print(res)
				return err
			}
		}
	}
	if len(a) == 3 && a[0] == "roles" && (a[1] == "run" || a[1] == "destroy") {
		return c.runRole(ctx, a[2], res)
	}
	return c.print(res)
}

func newClient(o options, cfg config, in io.Reader, out, errOut io.Writer) (*client, error) {
	server := firstOf(o.values["server"], os.Getenv("KORTA_SERVER"), cfg.Server, "http://127.0.0.1:8080")
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("the server must be an http(s) URL without credentials, query or fragment")
	}
	server = strings.TrimRight(server, "/")
	token := cfg.Token
	// A saved token is only ever sent to the manager it was saved for.
	if server != strings.TrimRight(cfg.Server, "/") {
		token = ""
	}
	if v := os.Getenv("KORTA_TOKEN"); v != "" {
		token = v
	}
	if f := o.values["token-file"]; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	noRedirects := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client{base: server, token: token, http: &http.Client{CheckRedirect: noRedirects}, in: in, out: out, errOut: errOut, opts: o}, nil
}

// checkTransport refuses to send the admin token in clear text to another
// machine, unless --insecure says the network is trusted.
func (c *client) checkTransport() error {
	if c.token == "" || c.opts.yes("insecure") {
		return nil
	}
	u, _ := url.Parse(c.base)
	if u.Scheme == "https" || isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing to send the admin token over plain HTTP to %s; use an https:// URL (put a TLS proxy in front of korta-server), or pass --insecure on a network you trust", u.Host)
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *client) login(ctx context.Context, path string) error {
	if len(c.opts.args) != 1 {
		return fmt.Errorf("usage: korta login [--server URL] [--token-file FILE]")
	}
	if c.token == "" {
		token, err := readToken(c.in, c.errOut)
		if err != nil {
			return err
		}
		if token == "" {
			return fmt.Errorf("no token given; it is in the manager's data directory as admin-token, or in KORTA_ADMIN_TOKEN")
		}
		c.token = token
	}
	if err := c.checkTransport(); err != nil {
		return err
	}
	if _, err := c.request(ctx, "GET", "/api/session", nil); err != nil {
		return err
	}
	if err := saveConfig(path, config{Server: c.base, Token: c.token}, io.Discard); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Signed in to %s. Credentials saved in %s.\n", c.base, path)
	return nil
}

func configPath(o options) (string, error) {
	if p := firstOf(o.values["config"], os.Getenv("KORTA_CONFIG")); p != "" {
		return p, nil
	}
	d, err := os.UserConfigDir()
	return filepath.Join(d, "korta", "config.json"), err
}

func loadConfig(path string) (config, error) {
	var cfg config
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	return cfg, nil
}

// saveConfig replaces the file atomically; it is created with mode 0600.
func saveConfig(path string, cfg config, out io.Writer) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	f, err := os.CreateTemp(filepath.Dir(path), ".korta-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	fmt.Fprintln(out, "Configuration saved.")
	return nil
}

func (c *client) request(ctx context.Context, method, path string, body []byte) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, c.connectionError(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = http.StatusText(res.StatusCode)
		}
		if res.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("HTTP 401: not signed in to %s (%s); run korta login, or set KORTA_TOKEN", c.base, e.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, e.Error)
	}
	if len(bytes.TrimSpace(b)) > 0 && !json.Valid(b) {
		return nil, fmt.Errorf("the server returned invalid JSON; is %s a Korta manager?", c.base)
	}
	return b, nil
}

func (c *client) connectionError(err error) error {
	var netErr *net.OpError
	if errors.As(err, &netErr) && netErr.Op == "dial" {
		return fmt.Errorf("cannot reach the manager at %s (%v); is korta-server running there? Choose another with --server or KORTA_SERVER", c.base, netErr.Err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("the request to %s timed out; raise --timeout if the manager is slow", c.base)
	}
	return fmt.Errorf("request to %s failed: %w", c.base, err)
}

// payload reads the request body from --file, --markdown or --data.
func (c *client) payload() ([]byte, error) {
	o := c.opts
	f, d := o.values["file"], o.values["data"]
	a := o.args
	roleInput := len(a) >= 2 && a[0] == "roles" && (a[1] == "create" || a[1] == "update" || a[1] == "preview")
	explicitMarkdown := roleInput && o.values["markdown"] != ""
	if explicitMarkdown {
		if f != "" || d != "" {
			return nil, fmt.Errorf("use only one of --markdown, --file or --data")
		}
		f = o.values["markdown"]
	}
	if f != "" && d != "" {
		return nil, fmt.Errorf("use either --file or --data")
	}
	var b []byte
	var err error
	switch {
	case f == "-":
		b, err = io.ReadAll(io.LimitReader(c.in, (1<<20)+1))
	case f != "":
		b, err = os.ReadFile(f)
	case d != "":
		b = []byte(d)
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("the request exceeds 1 MiB")
	}
	if roleInput && b != nil {
		dir := "."
		if f != "" && f != "-" {
			dir = filepath.Dir(f)
		}
		return c.rolePayload(b, explicitMarkdown, dir)
	}
	if b != nil && !json.Valid(b) {
		return nil, fmt.Errorf("the request must be valid JSON")
	}
	return b, nil
}

// version reports the -ldflags version, else the module version and the
// commit Go recorded at build time.
func version() string {
	info, ok := debug.ReadBuildInfo()
	v := firstOf(Version, "dev")
	// Pseudo-versions such as v0.0.0-20261030-abcdef only repeat the commit.
	if ok && Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" && !strings.HasPrefix(info.Main.Version, "v0.0.0-") {
		v = info.Main.Version
	}
	if !ok {
		return v
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if rev := settings["vcs.revision"]; rev != "" {
		v += " (commit " + rev[:min(12, len(rev))]
		if settings["vcs.modified"] == "true" {
			v += ", modified"
		}
		v += ")"
	}
	return v
}
