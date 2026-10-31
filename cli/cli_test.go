package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRoutes(t *testing.T) {
	cases := []struct{ args, method, path string }{
		{"health", "GET", "/api/health"}, {"types", "GET", "/api/types"}, {"session", "GET", "/api/session"}, {"ca", "GET", "/api/ca"},
		{"audit --target ins_1", "GET", "/api/audit?target=ins_1"},
		{"keys list", "GET", "/api/ssh-keys"}, {"keys create --data {}", "POST", "/api/ssh-keys"}, {"keys delete key_1", "DELETE", "/api/ssh-keys/key_1"},
		{"instances list", "GET", "/api/instances"}, {"instances get ins_1", "GET", "/api/instances/ins_1"}, {"instances create --data {}", "POST", "/api/instances"}, {"instances update ins_1 --data {}", "PUT", "/api/instances/ins_1"}, {"instances delete ins_1", "DELETE", "/api/instances/ins_1"}, {"instances check ins_1", "POST", "/api/instances/ins_1/check"}, {"instances trust-host-key ins_1", "POST", "/api/instances/ins_1/trust-host-key"}, {"instances console ins_1", "CONSOLE", "/api/instances/ins_1/console"},
		{"deployments list", "GET", "/api/deployments"}, {"deployments get dep_1", "GET", "/api/deployments/dep_1"}, {"deployments create --data {}", "POST", "/api/deployments"}, {"deployments update dep_1 --data {}", "PUT", "/api/deployments/dep_1/spec"}, {"deployments delete dep_1", "DELETE", "/api/deployments/dep_1"}, {"deployments apply dep_1", "POST", "/api/deployments/dep_1/apply"}, {"deployments connection dep_1 --role app --database orders", "GET", "/api/deployments/dep_1/connection?database=orders&role=app"}, {"deployments action dep_1 backup", "POST", "/api/deployments/dep_1/actions/backup"},
		{"roles list", "GET", "/api/roles"}, {"roles get role_1", "GET", "/api/roles/role_1"}, {"roles create --data {}", "POST", "/api/roles"}, {"roles update role_1 --data {}", "PUT", "/api/roles/role_1"}, {"roles delete role_1", "DELETE", "/api/roles/role_1"}, {"roles preview --data {}", "POST", "/api/roles/preview"}, {"roles plan role_1", "POST", "/api/roles/role_1/plan"}, {"roles apply role_1 --plan plan_1 --approve", "POST", "/api/roles/role_1/apply"},
		{"operations list", "GET", "/api/operations"}, {"operations get op_1", "GET", "/api/operations/op_1"}, {"operations wait op_1", "GET", "/api/operations/op_1"},
		{"assistant status", "GET", "/api/assistant"}, {"assistant start --role role_1", "POST", "/api/assistant/chats"}, {"assistant send chat_1 --text hello", "POST", "/api/assistant/chats/chat_1/messages"}, {"assistant save chat_1", "POST", "/api/assistant/chats/chat_1/save"},
		{"provision --data {}", "POST", "/api/provision"}, {"api GET /api/health", "GET", "/api/health"},
	}
	for _, action := range []string{"status", "logs", "restart", "rollback", "backup", "backups", "restore"} {
		cases = append(cases, struct{ args, method, path string }{"deployments " + action + " dep_1", "POST", "/api/deployments/dep_1/actions/" + action})
	}
	for _, tc := range cases {
		t.Run(tc.args, func(t *testing.T) {
			o, e := parse(strings.Fields(tc.args))
			if e != nil {
				t.Fatal(e)
			}
			c := client{opts: o, in: strings.NewReader("")}
			m, p, _, e := c.route()
			if e != nil || m != tc.method || p != tc.path {
				t.Fatalf("got %s %s %v", m, p, e)
			}
		})
	}
}
func TestValidation(t *testing.T) {
	for _, args := range []string{"roles apply role_1", "roles apply role_1 --plan op_1", "instances create", "deployments update dep_1", "roles delete ../x", "api GET /api/../x", "instances list extra", "provision --data nope", "health --file - --data {}"} {
		t.Run(args, func(t *testing.T) {
			o, e := parse(strings.Fields(args))
			if e == nil {
				c := client{opts: o, in: strings.NewReader("")}
				_, _, _, e = c.route()
			}
			if e == nil {
				t.Fatal("expected error")
			}
		})
	}
}
func runTest(t *testing.T, s *httptest.Server, args ...string) (string, error) {
	t.Helper()
	args = append([]string{"--server", s.URL, "--config", filepath.Join(t.TempDir(), "config.json")}, args...)
	var out bytes.Buffer
	err := Run(context.Background(), args, strings.NewReader(""), &out, io.Discard)
	return out.String(), err
}
func TestHTTPAndOperationFailures(t *testing.T) {
	t.Setenv("KORTA_TOKEN", "test-token")
	t.Setenv("KORTA_SERVER", "")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer")
		}
		switch r.URL.Path {
		case "/api/deployments":
			if r.Method != "POST" {
				t.Error(r.Method)
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"name":"test"}` {
				t.Errorf("body %s", b)
			}
			fmt.Fprint(w, `{"operation":{"id":"op_1","status":"running"}}`)
		case "/api/operations/op_1":
			fmt.Fprint(w, `{"id":"op_1","status":"failed","detail":"host unreachable"}`)
		default:
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		}
	}))
	defer s.Close()
	out, err := runTest(t, s, "deployments", "create", "--file", "-", "--wait")
	if err == nil {
		t.Fatal(out)
	} // Empty stdin is rejected before a request.
	out, err = runTest(t, s, "deployments", "create", "--data", `{"name":"test"}`, "--wait", "--json")
	if err == nil || !strings.Contains(out, `"failed"`) {
		t.Fatalf("%s %v", out, err)
	}
	if _, err = runTest(t, s, "instances", "list"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatal(err)
	}
}
func TestLoginPermissionsAndServerIsolation(t *testing.T) {
	t.Setenv("KORTA_TOKEN", "")
	t.Setenv("KORTA_SERVER", "")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"types":[]}`)
	}))
	defer s.Close()
	p := filepath.Join(t.TempDir(), "config.json")
	var out bytes.Buffer
	err := Run(context.Background(), []string{"login", "--server", s.URL, "--config", p}, strings.NewReader("secret-token\n"), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("saved credential leaked to another manager")
		}
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer other.Close()
	if err = Run(context.Background(), []string{"health", "--server", other.URL, "--config", p}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err = Run(context.Background(), []string{"logout", "--config", p}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "secret-token") {
		t.Fatal("logout retained token")
	}
}
func TestWaitCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"id":"op_1","status":"running"}`) }))
	defer s.Close()
	_, err := runTest(t, s, "operations", "wait", "op_1", "--timeout", "25ms")
	if err == nil {
		t.Fatal("wait ignored deadline")
	}
}
func TestConsoleProtocol(t *testing.T) {
	t.Setenv("KORTA_TOKEN", "console-token")
	t.Setenv("KORTA_SERVER", "")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/instances/ins_1/console" || r.Header.Get("Authorization") != "Bearer console-token" {
			t.Error("wrong console request")
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		kind, b, err := ws.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || string(b) != "hello" {
			t.Errorf("input %s %v", b, err)
			return
		}
		_ = ws.Write(ctx, websocket.MessageBinary, []byte("welcome"))
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"type":"closed","message":"done"}`))
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	defer s.Close()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	go func() { _, _ = w.Write([]byte("hello")) }()
	var out bytes.Buffer
	err := Run(context.Background(), []string{"--server", s.URL, "--config", filepath.Join(t.TempDir(), "config.json"), "instances", "console", "ins_1"}, r, &out, io.Discard)
	if err != nil || out.String() != "welcome" {
		t.Fatalf("%s %v", out.String(), err)
	}
}

func TestStdinAndInvalidOutputBeforeMutation(t *testing.T) {
	t.Setenv("KORTA_TOKEN", "token")
	t.Setenv("KORTA_SERVER", "")
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"name":"from-stdin"}` {
			t.Errorf("body: %s", b)
		}
		fmt.Fprint(w, `{"id":"dep_1"}`)
	}))
	defer s.Close()
	args := []string{"--server", s.URL, "--config", filepath.Join(t.TempDir(), "config.json"), "deployments", "create", "--file", "-"}
	if err := Run(context.Background(), args, strings.NewReader(`{"name":"from-stdin"}`), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	if err := Run(context.Background(), append(args, "--output", "typo"), strings.NewReader(`{"name":"from-stdin"}`), io.Discard, io.Discard); err == nil {
		t.Fatal("accepted invalid output")
	}
	if calls != 1 {
		t.Fatal("invalid flags caused a mutation")
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	t.Setenv("KORTA_TOKEN", "private-token")
	t.Setenv("KORTA_SERVER", "")
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect"); fmt.Fprint(w, `{}`) }))
	defer dest.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/api/session", http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	if _, err := runTest(t, s, "session"); err == nil {
		t.Fatal("redirect succeeded")
	}
}
