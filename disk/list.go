package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Device is one block device on a host, for choosing a disk to inspect. Only
// a device that Inspectable marks may be passed to Probe; Reason says why not.
type Device struct {
	Device      string   `json:"device"`
	StableIDs   []string `json:"stableIDs,omitempty"`
	Size        uint64   `json:"size"`
	Type        string   `json:"type"`
	Serial      string   `json:"serial,omitempty"`
	WWN         string   `json:"wwn,omitempty"`
	Filesystem  string   `json:"filesystem,omitempty"`
	Mountpoints []string `json:"mountpoints,omitempty"`
	Partitions  int      `json:"partitions"`
	Inspectable bool     `json:"inspectable"`
	Reason      string   `json:"reason,omitempty"`
}

// listScript prints lsblk's JSON for every top-level device, a line of "---",
// then one "TARGET LINK" line for each /dev/disk/by-id link.
const listScript = "set -eu\ncommand -v lsblk >/dev/null 2>&1 || { echo 'install lsblk (util-linux)'; exit 1; }\n" +
	"lsblk --bytes --json --paths --output NAME,MAJ:MIN,SIZE,TYPE,SERIAL,WWN,FSTYPE,UUID,MOUNTPOINTS\n" +
	"echo '---'\n" +
	"for l in /dev/disk/by-id/*; do [ -e \"$l\" ] || continue; printf '%s %s\\n' \"$(readlink -f \"$l\")\" \"$l\"; done\n"

// List reports every block device on the host and the stable IDs that name
// each one. It changes nothing.
func List(ctx context.Context, r Runner) ([]Device, error) {
	out, err := r.Run(ctx, listScript)
	if err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}
	return ParseList(out)
}

// ParseList validates the output of listScript. A device without a stable ID,
// with no serial or WWN, or with partitions is listed but not inspectable.
func ParseList(b []byte) ([]Device, error) {
	text := string(b)
	i := strings.Index(text, "\n---\n")
	if i < 0 && !strings.HasPrefix(text, "---\n") {
		return nil, fmt.Errorf("lsblk returned invalid device data")
	}
	var doc struct {
		Devices []struct {
			Name        string            `json:"name"`
			Size        uint64            `json:"size"`
			Type        string            `json:"type"`
			Serial      *string           `json:"serial"`
			WWN         *string           `json:"wwn"`
			FSType      *string           `json:"fstype"`
			Mountpoints []*string         `json:"mountpoints"`
			Children    []json.RawMessage `json:"children"`
		} `json:"blockdevices"`
	}
	jsonPart := text
	if i >= 0 {
		jsonPart = text[:i]
	}
	if err := json.Unmarshal([]byte(jsonPart), &doc); err != nil || doc.Devices == nil {
		return nil, fmt.Errorf("lsblk returned invalid device data")
	}
	links := map[string][]string{}
	if i >= 0 {
		for _, line := range strings.Split(text[i+len("\n---\n"):], "\n") {
			target, link, ok := strings.Cut(line, " ")
			if !ok || !strings.HasPrefix(link, "/dev/disk/by-id/") || !byID.MatchString(link) {
				continue
			}
			links[target] = append(links[target], link)
		}
	}
	devices := make([]Device, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		if !strings.HasPrefix(d.Name, "/dev/") || d.Size == 0 || d.Type == "" {
			return nil, fmt.Errorf("lsblk did not identify a device completely")
		}
		val := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		dev := Device{Device: d.Name, StableIDs: links[d.Name], Size: d.Size, Type: d.Type, Serial: val(d.Serial), WWN: val(d.WWN), Filesystem: val(d.FSType), Partitions: len(d.Children)}
		for _, m := range d.Mountpoints {
			if m != nil && *m != "" {
				dev.Mountpoints = append(dev.Mountpoints, *m)
			}
		}
		switch {
		case len(dev.StableIDs) == 0:
			dev.Reason = "no /dev/disk/by-id link"
		case dev.Serial == "" && dev.WWN == "":
			dev.Reason = "no serial number or WWN"
		case dev.Partitions > 0:
			dev.Reason = "has partitions; inspect them individually"
		default:
			dev.Inspectable = true
		}
		devices = append(devices, dev)
	}
	return devices, nil
}
