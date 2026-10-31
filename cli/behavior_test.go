package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeManager answers a fixed set of routes and records request bodies.
type fakeManager struct {
	routes map[string]string // "METHOD /path" -> JSON response
	bodies map[string]string
}

func (f *fakeManager) start(t *testing.T) *httptest.Server {
	t.Helper()
	f.bodies = map[string]string{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		b, _ := io.ReadAll(r.Body)
		f.bodies[key] = string(b)
		res, ok := f.routes[key]
		if !ok {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		fmt.Fprint(w, res)
	}))
	t.Cleanup(s.Close)
	return s
}

func run(t *testing.T, server string, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("KORTA_TOKEN", "test-token")
	t.Setenv("KORTA_SERVER", "")
	args = append([]string{"--server", server, "--config", filepath.Join(t.TempDir(), "config.json")}, args...)
	var out, errOut bytes.Buffer
	err = Run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestConsoleIgnoresCommandTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		time.Sleep(150 * time.Millisecond)
		_ = ws.Write(r.Context(), websocket.MessageBinary, []byte("still here"))
		_ = ws.Write(r.Context(), websocket.MessageText, []byte(`{"type":"closed","message":"The remote shell ended."}`))
	}))
	defer s.Close()
	t.Setenv("KORTA_TOKEN", "test-token")
	stdin, w := io.Pipe() // stays open like a terminal
	defer w.Close()
	var out, errOut bytes.Buffer
	err := Run(context.Background(), []string{"--server", s.URL, "--config", filepath.Join(t.TempDir(), "c.json"), "instances", "console", "ins_1", "--timeout", "20ms"}, stdin, &out, &errOut)
	if err != nil || out.String() != "still here" || !strings.Contains(errOut.String(), "The remote shell ended.") {
		t.Fatalf("%q %q %v", out.String(), errOut.String(), err)
	}
}

func TestPreviewFailsOnMarkdownMistakes(t *testing.T) {
	f := &fakeManager{routes: map[string]string{"POST /api/roles/preview": `{"error":"line 2: cannot tell what \"frobnicated\" means","steps":[]}`}}
	s := f.start(t)
	_, _, err := run(t, s.URL, "# Users\n- test frobnicated\n", "roles", "preview", "--markdown", "-")
	if err == nil || !strings.Contains(err.Error(), "line 2: cannot tell") {
		t.Fatal(err)
	}
	f.routes["POST /api/roles/preview"] = `{"steps":[{"type":"group","name":"Group database"},{"type":"user","name":"test added to database group"}],"risks":[]}`
	out, _, err := run(t, s.URL, "# Users\n- test added to database group\n", "roles", "preview", "--markdown", "-")
	if err != nil || !strings.Contains(out, " 2. user       test added to database group") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestTokenNeverSentInClearToOtherHosts(t *testing.T) {
	for _, server := range []string{"http://10.0.0.5:8080", "http://korta.example.com"} {
		_, _, err := run(t, server, "", "instances", "list")
		if err == nil || !strings.Contains(err.Error(), "plain HTTP") {
			t.Fatalf("%s: %v", server, err)
		}
	}
	// Loopback is fine, and --insecure is an explicit choice.
	f := &fakeManager{routes: map[string]string{"GET /api/instances": `[]`}}
	s := f.start(t)
	if _, _, err := run(t, s.URL, "", "instances", "list"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, "http://192.0.2.1:9", "", "health", "--insecure", "--timeout", "100ms"); err == nil || strings.Contains(err.Error(), "plain HTTP") {
		t.Fatal(err)
	}
}

func TestLogsWaitAndPrintPlainText(t *testing.T) {
	f := &fakeManager{routes: map[string]string{
		"POST /api/deployments/dep_1/actions/logs": `{"id":"op_1","title":"logs shop","status":"running"}`,
		"GET /api/operations/op_1": `{"id":"op_1","title":"logs shop","status":"succeeded","steps":[{"name":"Read logs","status":"succeeded"}],
			"result":{"hosts":[{"instance":"web1","output":"2026-10-30 started\n2026-10-30 listening on 3000\n"}]}}`,
	}}
	s := f.start(t)
	out, errOut, err := run(t, s.URL, "", "deployments", "logs", "dep_1")
	if err != nil || out != "== web1\n2026-10-30 started\n2026-10-30 listening on 3000\n" {
		t.Fatalf("%q %v", out, err)
	}
	if !strings.Contains(errOut, "logs shop (op_1)") || !strings.Contains(errOut, "ok     Read logs") {
		t.Fatalf("progress: %q", errOut)
	}
	// --wait=false returns the running operation at once.
	out, _, err = run(t, s.URL, "", "deployments", "logs", "dep_1", "--wait=false")
	if err != nil || !strings.Contains(out, "korta operations wait op_1") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestPlanTableAndApplyCurrentPlan(t *testing.T) {
	run1 := `{"kind":"plan","roleID":"role_1","changes":1,"failed":0,"hosts":[{"instance":"db1","status":"changed","steps":[{"step":1,"name":"Group database","status":"changed","detail":"would create"},{"step":2,"name":"/opt/db","status":"ok","detail":"up to date"}]}]}`
	f := &fakeManager{routes: map[string]string{
		"POST /api/roles/role_1/plan":  `{"id":"op_9","title":"Plan role users v1","status":"running"}`,
		"GET /api/operations/op_9":     `{"id":"op_9","title":"Plan role users v1","status":"succeeded","steps":[{"name":"db1: 1 changed, 1 ok, 0 failed","status":"succeeded"}],"result":` + run1 + `}`,
		"GET /api/roles/role_1":        `{"id":"role_1","name":"users","version":1,"risks":["step 3 removes a user"],"plan":{"operationID":"op_9","instanceIDs":["ins_1"],"changes":1}}`,
		"POST /api/roles/role_1/apply": `{"id":"op_10","title":"Apply role users v1","status":"running"}`,
	}}
	s := f.start(t)
	out, _, err := run(t, s.URL, "", "roles", "plan", "role_1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"db1       1. Group database  will change  would create", "2. /opt/db", "1 change on 1 instance.", "korta roles apply role_1 --approve"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	_, errOut, err := run(t, s.URL, "", "roles", "apply", "role_1", "--approve")
	if err != nil || !strings.Contains(f.bodies["POST /api/roles/role_1/apply"], `"planID":"op_9"`) {
		t.Fatalf("%v %s", err, f.bodies["POST /api/roles/role_1/apply"])
	}
	if !strings.Contains(errOut, "Approving plan op_9 for users v1: 1 change on 1 instance.") || !strings.Contains(errOut, "review: step 3 removes a user") {
		t.Fatal(errOut)
	}
	f.routes["GET /api/roles/role_1"] = `{"id":"role_1","name":"users","version":2}`
	if _, _, err = run(t, s.URL, "", "roles", "apply", "role_1", "--approve"); err == nil || !strings.Contains(err.Error(), "no valid plan") {
		t.Fatal(err)
	}
}

func TestCreateFromFlags(t *testing.T) {
	cases := []struct {
		args string
		want map[string]any
	}{
		{"instances create db1 --host 10.0.0.5 --user ubuntu --key key_1 --port 2222 --label env=prod --label team=data",
			map[string]any{"name": "db1", "labels": map[string]any{"env": "prod", "team": "data"}, "ssh": map[string]any{"host": "10.0.0.5", "user": "ubuntu", "secretID": "key_1", "port": float64(2222)}}},
		{"deployments create shop-db --type postgres --instance ins_1",
			map[string]any{"name": "shop-db", "type": "postgres", "instanceIDs": []any{"ins_1"}, "spec": map[string]any{}}},
		{`deployments create shop-db --type postgres --instance ins_1 --data {"version":"17"}`,
			map[string]any{"name": "shop-db", "type": "postgres", "instanceIDs": []any{"ins_1"}, "spec": map[string]any{"version": "17"}}},
	}
	for _, tc := range cases {
		o, err := parse(strings.Fields(tc.args))
		if err != nil {
			t.Fatal(err)
		}
		c := client{opts: o, in: strings.NewReader("")}
		_, _, body, err := c.route()
		var got map[string]any
		if err != nil || json.Unmarshal(body, &got) != nil || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Fatalf("%s: %s %v", tc.args, body, err)
		}
	}
	for _, args := range []string{"instances create db1 --host h", "deployments create x --type postgres", "instances create db1 --host h --user u --key k --port 0"} {
		o, _ := parse(strings.Fields(args))
		c := client{opts: o, in: strings.NewReader("")}
		if _, _, _, err := c.route(); err == nil {
			t.Fatalf("accepted %s", args)
		}
	}
}

func TestTablesAndSuggestions(t *testing.T) {
	f := &fakeManager{routes: map[string]string{
		"GET /api/instances":   `[{"id":"ins_1","name":"db1","ssh":{"host":"10.0.0.5","user":"ubuntu","port":2222},"os":{"distro":"ubuntu","version":"24.04","arch":"amd64"},"status":"ready","labels":{"env":"prod"}}]`,
		"GET /api/deployments": `[]`,
	}}
	s := f.start(t)
	out, _, err := run(t, s.URL, "", "instances", "list")
	if err != nil || !strings.Contains(out, "ubuntu@10.0.0.5:2222") || !strings.Contains(out, "ubuntu 24.04 amd64") || !strings.Contains(out, "env=prod") {
		t.Fatalf("%s %v", out, err)
	}
	if out, _, _ = run(t, s.URL, "", "deployments", "list"); !strings.HasPrefix(out, "No deployments.") {
		t.Fatal(out)
	}
	for args, want := range map[string]string{
		"instances lst":     `did you mean "instances list"`,
		"instanes list":     `did you mean "instances"`,
		"roles list --jsn":  "did you mean --json",
		"keys frobnicate x": "keys takes: list, create, delete",
		"health -v":         "unknown flag -v",
	} {
		_, _, err := run(t, s.URL, "", strings.Fields(args)...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", args, err)
		}
	}
}

func TestConnectionHintLoginPromptAndVersion(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close()
	if _, _, err := run(t, url, "", "health"); err == nil || !strings.Contains(err.Error(), "is korta-server running there?") {
		t.Fatal(err)
	}
	f := &fakeManager{routes: map[string]string{"GET /api/session": `{"authenticated":true}`}}
	ok := f.start(t)
	t.Setenv("KORTA_TOKEN", "")
	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"login", "--server", ok.URL, "--config", filepath.Join(t.TempDir(), "c.json")}, strings.NewReader("piped-token\n"), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if errOut.Len() != 0 || !strings.HasPrefix(out.String(), "Signed in to "+ok.URL) {
		t.Fatalf("%q %q", out.String(), errOut.String())
	}
	out.Reset()
	if err := Run(context.Background(), []string{"version"}, nil, &out, io.Discard); err != nil || !strings.HasPrefix(out.String(), "korta ") {
		t.Fatal(out.String(), err)
	}
}
