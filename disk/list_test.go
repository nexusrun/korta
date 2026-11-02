package disk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type listRunner struct {
	out    string
	err    error
	script string
}

func (r *listRunner) Run(_ context.Context, script string) ([]byte, error) {
	r.script = script
	return []byte(r.out), r.err
}

const oneDisk = `{"blockdevices":[{"name":"/dev/sdb","maj:min":"8:16","size":1073741824,"type":"disk","serial":"vol-123","wwn":null,"fstype":null,"uuid":null,"mountpoints":[null]}]}`

func TestParseListInspectable(t *testing.T) {
	out := oneDisk + "\n---\n/dev/sdb /dev/disk/by-id/virtio-vol-123\n/dev/sdb /dev/disk/by-id/wwn-0x5000\n"
	devs, err := ParseList([]byte(out))
	if err != nil || len(devs) != 1 {
		t.Fatalf("%v %v", devs, err)
	}
	d := devs[0]
	if !d.Inspectable || d.Reason != "" || d.Serial != "vol-123" || len(d.StableIDs) != 2 || d.StableIDs[0] != "/dev/disk/by-id/virtio-vol-123" {
		t.Fatalf("%+v", d)
	}
	if d.Size != 1073741824 || d.Partitions != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestParseListReasons(t *testing.T) {
	cases := map[string]struct {
		json, links, reason string
	}{
		"no stable id": {oneDisk, "", "no /dev/disk/by-id link"},
		"no serial or WWN": {`{"blockdevices":[{"name":"/dev/sdc","maj:min":"8:32","size":5,"type":"disk","serial":null,"wwn":null}]}`,
			"/dev/sdc /dev/disk/by-id/scsi-x", "no serial number or WWN"},
		"partitions": {`{"blockdevices":[{"name":"/dev/sdd","maj:min":"8:48","size":5,"type":"disk","serial":"s","children":[{"name":"/dev/sdd1"}]}]}`,
			"/dev/sdd /dev/disk/by-id/virtio-s", "has partitions; inspect them individually"},
	}
	for name, c := range cases {
		out := c.json + "\n---\n" + c.links
		if c.links != "" {
			out += "\n"
		}
		devs, err := ParseList([]byte(out))
		if err != nil || len(devs) != 1 {
			t.Fatalf("%s: %v %v", name, devs, err)
		}
		if devs[0].Inspectable || devs[0].Reason != c.reason {
			t.Fatalf("%s: %+v", name, devs[0])
		}
	}
}

func TestParseListIgnoresPartitionLinks(t *testing.T) {
	out := oneDisk + "\n---\n/dev/sdb1 /dev/disk/by-id/virtio-vol-123-part1\n/dev/sdb /dev/disk/by-id/virtio-vol-123\n"
	devs, err := ParseList([]byte(out))
	if err != nil || len(devs) != 1 || len(devs[0].StableIDs) != 1 || devs[0].StableIDs[0] != "/dev/disk/by-id/virtio-vol-123" {
		t.Fatalf("%+v %v", devs, err)
	}
}

func TestParseListRejectsBadOutput(t *testing.T) {
	for _, bad := range []string{"", "not json", `{"blockdevices":null}`, `{"blockdevices":[{"name":"sdb","size":1,"type":"disk"}]}`, `{"blockdevices":[{"name":"/dev/sdb","size":0,"type":"disk"}]}`} {
		if _, err := ParseList([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestListRunsReadOnlyScript(t *testing.T) {
	r := &listRunner{out: oneDisk + "\n---\n"}
	devs, err := List(context.Background(), r)
	if err != nil || len(devs) != 1 || devs[0].Inspectable {
		t.Fatalf("%+v %v", devs, err)
	}
	if !strings.Contains(r.script, "lsblk") || !strings.Contains(r.script, "/dev/disk/by-id/") || strings.Contains(r.script, "wipefs") {
		t.Fatalf("script: %s", r.script)
	}
	r = &listRunner{err: errors.New("SSH failed")}
	if _, err := List(context.Background(), r); err == nil {
		t.Fatal("ignored failure")
	}
}
