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

func TestDiskInspectUsesInventory(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
cat >/dev/null
printf '%s\n' '{"blockdevices":[{"name":"/dev/sdb","maj:min":"8:16","size":1073741824,"type":"disk","serial":"vol-123","wwn":null,"fstype":null,"uuid":null,"mountpoints":[null]}]}'
`
	if err := os.WriteFile(ssh, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv := filepath.Join(dir, "hosts.md")
	if err := os.WriteFile(inv, []byte("# Hosts\n- web1 192.0.2.1 env=prod\n- web2 192.0.2.2 env=dev\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Run(context.Background(), []string{"disk", "inspect", "/dev/disk/by-id/virtio-vol-123", "-i", inv, "--limit", "env=prod", "--json"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var rows []diskResult
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0].Host != "web1" || rows[0].Observation == nil || rows[0].Observation.Serial != "vol-123" {
		t.Fatalf("%s: %v", out.String(), err)
	}
}
