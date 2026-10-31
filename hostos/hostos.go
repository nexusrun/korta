// Package hostos detects the operating system of an SSH-reachable host.
package hostos

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Profile is what deployment types need to know about a host.
type Profile struct {
	Distro   string `json:"distro"`   // ubuntu, debian, rhel, rocky, almalinux, centos
	Version  string `json:"version"`  // VERSION_ID, e.g. 24.04 or 9.4
	Codename string `json:"codename"` // apt hosts only, e.g. noble
	Family   string `json:"family"`   // apt or rpm
	Arch     string `json:"arch"`     // amd64 or arm64
	Hostname string `json:"hostname"`
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memoryMB"`
	// Details shown to operators; deployment types do not depend on them.
	PrettyName string    `json:"prettyName,omitempty"`
	Kernel     string    `json:"kernel,omitempty"`
	CPUModel   string    `json:"cpuModel,omitempty"`
	DiskMB     int       `json:"diskMB,omitempty"` // root filesystem size
	DiskUsedMB int       `json:"diskUsedMB,omitempty"`
	Addresses  []Address `json:"addresses,omitempty"`
}

// Address is a global-scope IP address on a network interface.
type Address struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	Family    string `json:"family"` // ipv4 or ipv6
}

// Major returns the major version, e.g. 9 for "9.4" and 24 for "24.04".
func (p Profile) Major() int {
	n, _ := strconv.Atoi(strings.SplitN(p.Version, ".", 2)[0])
	return n
}

// Script prints one KORTA_HOST line plus KORTA_INFO and KORTA_ADDR detail
// lines. It needs only POSIX sh, /etc/os-release and, for addresses, iproute2.
const Script = `set -eu
. /etc/os-release
mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
printf 'KORTA_HOST id=%s version=%s codename=%s arch=%s hostname=%s cpus=%s mem_kb=%s\n' \
  "${ID:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "$(uname -m)" "$(hostname -f 2>/dev/null || hostname)" "$(nproc)" "$mem"
printf 'KORTA_INFO pretty_name %s\n' "${PRETTY_NAME:-}"
printf 'KORTA_INFO kernel %s\n' "$(uname -r)"
cpu=$(awk -F: '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
[ -n "$cpu" ] || cpu=$(lscpu 2>/dev/null | awk -F: '/^Model name/ {print $2; exit}')
printf 'KORTA_INFO cpu_model %s\n' "$cpu"
printf 'KORTA_INFO disk_kb %s\n' "$(df -Pk / | awk 'NR==2 {print $2 " " $3}')"
if command -v ip >/dev/null 2>&1; then
  ip -o addr show scope global 2>/dev/null | awk '{print "KORTA_ADDR " $2 " " $3 " " $4}'
else
  # Without iproute2, interface names and prefix lengths are unknown.
  for a in $(hostname -I 2>/dev/null); do
    case "$a" in *:*) printf 'KORTA_ADDR - inet6 %s/128\n' "$a" ;; *) printf 'KORTA_ADDR - inet %s/32\n' "$a" ;; esac
  done
fi
`

var (
	tokenPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{0,64}$`)
	ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9._@:-]{1,32}$`)
	supported    = map[string]struct {
		family string
		majors []int
	}{
		"ubuntu":    {"apt", []int{22, 24}},
		"debian":    {"apt", []int{12, 13}},
		"rhel":      {"rpm", []int{8, 9, 10}},
		"rocky":     {"rpm", []int{8, 9, 10}},
		"almalinux": {"rpm", []int{8, 9, 10}},
		"centos":    {"rpm", []int{9, 10}},
	}
)

// Parse reads Script output and rejects unsupported or unexpected hosts.
func Parse(out []byte) (Profile, error) {
	var line string
	details := Profile{}
	for _, l := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(l, "KORTA_HOST "):
			line = strings.TrimPrefix(l, "KORTA_HOST ")
		case strings.HasPrefix(l, "KORTA_INFO "):
			parseInfo(&details, strings.TrimPrefix(l, "KORTA_INFO "))
		case strings.HasPrefix(l, "KORTA_ADDR "):
			if a, ok := parseAddress(strings.Fields(strings.TrimPrefix(l, "KORTA_ADDR "))); ok && len(details.Addresses) < 64 {
				details.Addresses = append(details.Addresses, a)
			}
		}
	}
	if line == "" {
		return Profile{}, fmt.Errorf("host did not report its operating system")
	}
	f := map[string]string{}
	for _, field := range strings.Fields(line) {
		k, v, _ := strings.Cut(field, "=")
		if !tokenPattern.MatchString(v) {
			return Profile{}, fmt.Errorf("host reported an invalid %s", k)
		}
		f[k] = v
	}
	p := details
	p.Distro, p.Version, p.Codename, p.Hostname = f["id"], f["version"], f["codename"], f["hostname"]
	switch f["arch"] {
	case "x86_64", "amd64":
		p.Arch = "amd64"
	case "aarch64", "arm64":
		p.Arch = "arm64"
	default:
		return Profile{}, fmt.Errorf("unsupported CPU architecture %q; use amd64 or arm64", f["arch"])
	}
	p.CPUs, _ = strconv.Atoi(f["cpus"])
	memKB, _ := strconv.Atoi(f["mem_kb"])
	p.MemoryMB = memKB / 1024
	s, ok := supported[p.Distro]
	if !ok {
		return Profile{}, fmt.Errorf("unsupported operating system %q; use Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux or CentOS Stream", p.Distro)
	}
	p.Family = s.family
	major := p.Major()
	for _, m := range s.majors {
		if m == major {
			if p.Family == "apt" && p.Codename == "" {
				return Profile{}, fmt.Errorf("host did not report a release codename")
			}
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("unsupported %s release %s; supported major versions: %v", p.Distro, p.Version, s.majors)
}

// clean keeps printable text only, trimmed and capped, since details are
// reported by the host and shown to operators.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func parseInfo(p *Profile, rest string) {
	key, value, _ := strings.Cut(rest, " ")
	value = clean(value)
	if value == "-" {
		value = ""
	}
	switch key {
	case "pretty_name":
		p.PrettyName = value
	case "kernel":
		p.Kernel = value
	case "cpu_model":
		p.CPUModel = value
	case "disk_kb":
		f := strings.Fields(value)
		if len(f) == 2 {
			total, err1 := strconv.Atoi(f[0])
			used, err2 := strconv.Atoi(f[1])
			if err1 == nil && err2 == nil {
				p.DiskMB, p.DiskUsedMB = total/1024, used/1024
			}
		}
	}
}

func parseAddress(f []string) (Address, bool) {
	if len(f) != 3 || !ifacePattern.MatchString(f[0]) {
		return Address{}, false
	}
	prefix, err := netip.ParsePrefix(f[2])
	if err != nil {
		return Address{}, false
	}
	family := "ipv4"
	if prefix.Addr().Is6() {
		family = "ipv6"
	}
	if (f[1] == "inet") != (family == "ipv4") {
		return Address{}, false
	}
	return Address{Interface: f[0], CIDR: prefix.String(), Family: family}, true
}
