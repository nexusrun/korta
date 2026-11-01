package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkInspectUsesInventory(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case "$(cat)" in
 *"address show dev eth0"*) echo '[{"ifname":"eth0"}]' ;;
 *"-4 route show dev eth0"*) echo '[{"dst":"default","gateway":"10.0.0.1"}]' ;;
 *"-6 route show dev eth0"*) echo '[]' ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inventory := filepath.Join(dir, "hosts.md")
	if err := os.WriteFile(inventory, []byte("# Hosts\n- web1 192.0.2.1 env=prod\n- web2 192.0.2.2 env=dev\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Run(context.Background(), []string{"network", "inspect", "eth0", "-i", inventory, "--limit", "env=prod", "--json"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var results []networkResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil || len(results) != 1 || results[0].Host != "web1" || results[0].Observation == nil || !strings.Contains(string(results[0].Observation.IPv4Routes), "10.0.0.1") {
		t.Fatalf("%s: %v", out.String(), err)
	}
}

func TestNetworkInspectUsage(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"network", "inspect"}, strings.NewReader(""), &out, io.Discard); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatal(err)
	}
}
