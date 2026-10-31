package hostos

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, out, family, err string
	}{
		{"ubuntu", "noise\nKORTA_HOST id=ubuntu version=24.04 codename=noble arch=x86_64 hostname=db1 cpus=4 mem_kb=8048000\n", "apt", ""},
		{"rocky", "KORTA_HOST id=rocky version=9.4 codename= arch=aarch64 hostname=db2 cpus=2 mem_kb=4024000", "rpm", ""},
		{"old ubuntu", "KORTA_HOST id=ubuntu version=20.04 codename=focal arch=x86_64 hostname=a cpus=1 mem_kb=1", "", "unsupported ubuntu release"},
		{"alpine", "KORTA_HOST id=alpine version=3.20 codename= arch=x86_64 hostname=a cpus=1 mem_kb=1", "", "unsupported operating system"},
		{"arm32", "KORTA_HOST id=debian version=12 codename=bookworm arch=armv7l hostname=a cpus=1 mem_kb=1", "", "unsupported CPU"},
		{"injection", "KORTA_HOST id=ubuntu version=24.04;rm codename=noble arch=x86_64 hostname=a cpus=1 mem_kb=1", "", "invalid version"},
		{"missing", "hello", "", "did not report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.out))
			if tc.err != "" {
				if err == nil || !contains(err.Error(), tc.err) {
					t.Fatalf("got %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || p.Family != tc.family || p.MemoryMB == 0 {
				t.Fatalf("got %+v %v", p, err)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseDetailsAndAddresses(t *testing.T) {
	out := "KORTA_HOST id=rocky version=9.4 codename= arch=x86_64 hostname=db1 cpus=4 mem_kb=8048000\n" +
		"KORTA_INFO pretty_name Rocky Linux 9.4 (Blue Onyx)\n" +
		"KORTA_INFO kernel 5.14.0-427.el9.x86_64\n" +
		"KORTA_INFO cpu_model  Intel(R) Xeon(R) Gold 6338 \x1b[31mCPU\n" +
		"KORTA_INFO disk_kb 41922560 10485760\n" +
		"KORTA_ADDR eth0 inet 10.0.1.15/24\n" +
		"KORTA_ADDR eth0 inet6 2001:db8::15/64\n" +
		"KORTA_ADDR eth1 inet 2001:db8::99/64\n" +
		"KORTA_ADDR bad;iface inet 10.0.0.1/8\n" +
		"KORTA_ADDR eth2 inet not-an-ip\n"
	p, err := Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if p.PrettyName != "Rocky Linux 9.4 (Blue Onyx)" || p.Kernel != "5.14.0-427.el9.x86_64" || p.DiskMB != 40940 || p.DiskUsedMB != 10240 {
		t.Fatalf("%+v", p)
	}
	if strings.ContainsRune(p.CPUModel, 0x1b) || !strings.HasPrefix(p.CPUModel, "Intel(R) Xeon(R) Gold 6338") {
		t.Fatalf("control characters kept: %q", p.CPUModel)
	}
	if len(p.Addresses) != 2 || p.Addresses[0] != (Address{"eth0", "10.0.1.15/24", "ipv4"}) || p.Addresses[1] != (Address{"eth0", "2001:db8::15/64", "ipv6"}) {
		t.Fatalf("%+v", p.Addresses)
	}
}
