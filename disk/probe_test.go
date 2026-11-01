package disk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	output string
	err    error
	script string
}

func (f *fakeRunner) Run(_ context.Context, s string) ([]byte, error) {
	f.script = s
	return []byte(f.output), f.err
}

func TestProbeRequiresStableIdentity(t *testing.T) {
	const valid = `{"blockdevices":[{"name":"/dev/sdb","maj:min":"8:16","size":1073741824,"type":"disk","serial":"vol-123","wwn":null,"fstype":null,"uuid":null,"mountpoints":[null]}]}`
	for _, tc := range []struct {
		name, path, out string
		fail            bool
	}{
		{"valid", "/dev/disk/by-id/virtio-vol-123", valid, false},
		{"direct device", "/dev/sdb", valid, true},
		{"shell injection", "/dev/disk/by-id/evil;id", valid, true},
		{"no identity", "/dev/disk/by-id/test", strings.Replace(valid, `"vol-123"`, `null`, 1), true},
		{"no size", "/dev/disk/by-id/test", strings.Replace(valid, `1073741824`, `0`, 1), true},
		{"children fail closed", "/dev/disk/by-id/test", strings.Replace(valid, `"mountpoints":[null]`, `"mountpoints":[null],"children":[{}]`, 1), true},
		{"bad JSON", "/dev/disk/by-id/test", "{}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{output: tc.out}
			got, err := Probe(context.Background(), r, tc.path)
			if (err != nil) != tc.fail {
				t.Fatalf("%+v: %v", got, err)
			}
			if err == nil && (got.Serial != "vol-123" || got.Size != 1073741824) {
				t.Fatalf("%+v", got)
			}
			if strings.Contains(tc.path, ";") && r.script != "" {
				t.Fatal("unsafe path reached shell")
			}
		})
	}
	r := &fakeRunner{err: errors.New("ssh failed")}
	if _, err := Probe(context.Background(), r, "/dev/disk/by-id/test"); err == nil {
		t.Fatal("ignored SSH failure")
	}
}
