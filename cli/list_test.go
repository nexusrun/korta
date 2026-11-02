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

// fakeSSH installs an ssh that prints output for every host, and an inventory
// with two hosts, web1 in prod and web2 in dev.
func listFakeSSH(t *testing.T, output string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\ncat <<'KORTA_EOF'\n" + output + "\nKORTA_EOF\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv := filepath.Join(dir, "hosts.md")
	if err := os.WriteFile(inv, []byte("# Hosts\n- web1 192.0.2.1 env=prod\n- web2 192.0.2.2 env=dev\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestDiskListShowsStableIDs(t *testing.T) {
	inv := listFakeSSH(t, `{"blockdevices":[{"name":"/dev/sdb","maj:min":"8:16","size":1073741824,"type":"disk","serial":"vol-123","wwn":null,"fstype":null,"uuid":null,"mountpoints":[null]},{"name":"/dev/sdc","maj:min":"8:32","size":5,"type":"disk","serial":null,"wwn":null,"fstype":null,"uuid":null,"mountpoints":[null]}]}
---
/dev/sdb /dev/disk/by-id/virtio-vol-123`)
	var out bytes.Buffer
	err := Run(context.Background(), []string{"disk", "list", "-i", inv, "--limit", "env=prod", "--json"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var rows []diskListRow
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("%s: %v", out.String(), err)
	}
	if len(rows) != 2 || rows[0].Host != "web1" || rows[0].Device != "/dev/sdb" || rows[0].StableIDs != "/dev/disk/by-id/virtio-vol-123" || !rows[0].Inspectable {
		t.Fatalf("%+v", rows)
	}
	if rows[1].Inspectable || rows[1].Reason != "no /dev/disk/by-id link" {
		t.Fatalf("unnamed disk marked inspectable: %+v", rows[1])
	}
}

func TestNetworkListShowsInterfaces(t *testing.T) {
	inv := listFakeSSH(t, `[{"ifname":"eth0","operstate":"UP","mtu":9001,"address":"02:11:22:33:44:55","addr_info":[{"local":"10.0.0.5","prefixlen":24}]}]`)
	var out bytes.Buffer
	err := Run(context.Background(), []string{"network", "list", "-i", inv, "--limit", "env=prod", "--json"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var rows []networkListRow
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0].Interface != "eth0" || rows[0].Addresses != "10.0.0.5/24" || !rows[0].Inspectable {
		t.Fatalf("%s: %v", out.String(), err)
	}
}

func TestListRejectsExtraArguments(t *testing.T) {
	for _, args := range [][]string{{"disk", "list", "extra", "-i", "x"}, {"network", "list", "extra", "-i", "x"}} {
		if err := Run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
