package hostnetwork

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type runner struct {
	calls    []string
	response []string
	err      error
}

func (r *runner) Run(_ context.Context, command string) ([]byte, error) {
	r.calls = append(r.calls, command)
	if r.err != nil {
		return nil, r.err
	}
	out := r.response[len(r.calls)-1]
	return []byte(out), nil
}

func TestInspect(t *testing.T) {
	r := &runner{response: []string{`[{"ifname":"eth0"}]`, `[{"dst":"default","gateway":"10.0.0.1"}]`, `[]`}}
	got, err := Inspect(context.Background(), r, "eth0")
	if err != nil || got.Interface != "eth0" || len(r.calls) != 3 || !strings.Contains(string(got.IPv4Routes), "10.0.0.1") {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"", "eth0;id", "../eth0", "abcdefghijklmnop"} {
		r := &runner{}
		if _, err := Inspect(context.Background(), r, bad); err == nil || len(r.calls) != 0 {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, input := range []string{`null`, `{}`, `[]`, `not json`} {
		r := &runner{response: []string{input}}
		if _, err := Inspect(context.Background(), r, "eth0"); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	r = &runner{err: errors.New("SSH failed")}
	if _, err := Inspect(context.Background(), r, "eth0"); err == nil {
		t.Fatal("ignored command failure")
	}
}
