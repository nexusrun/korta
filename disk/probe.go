// Package disk inspects explicitly named Linux block devices for disk plans.
// It does not change devices or authorize disk operations.
package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Runner executes a script on the host being inspected.
type Runner interface {
	Run(context.Context, string) ([]byte, error)
}

// Observation describes one exact device at a point in time. Callers must
// compare a fresh observation to the approved plan before changing the host.
type Observation struct {
	Requested   string        `json:"requested"`
	Device      string        `json:"device"`
	MajorMinor  string        `json:"majorMinor"`
	Size        uint64        `json:"size"`
	Type        string        `json:"type"`
	Serial      string        `json:"serial,omitempty"`
	WWN         string        `json:"wwn,omitempty"`
	Filesystem  string        `json:"filesystem,omitempty"`
	UUID        string        `json:"uuid,omitempty"`
	Mountpoints []string      `json:"mountpoints,omitempty"`
	Children    []Observation `json:"children,omitempty"`
}

var byID = regexp.MustCompile(`^/dev/disk/by-id/[A-Za-z0-9][A-Za-z0-9._:+-]{0,220}$`)

// Probe accepts only an explicit stable by-id path and requests JSON output.
// The shell argument is constrained by byID, which excludes shell syntax.
func Probe(ctx context.Context, r Runner, path string) (Observation, error) {
	if !byID.MatchString(path) {
		return Observation{}, fmt.Errorf("choose an explicit /dev/disk/by-id/ device; inspect the host for its stable ID")
	}
	script := "set -eu\ncommand -v lsblk >/dev/null 2>&1 || { echo 'install lsblk (util-linux)'; exit 1; }\n" +
		"test -b '" + path + "' || { echo 'disk is not a block device'; exit 1; }\n" +
		"lsblk --bytes --json --paths --output NAME,MAJ:MIN,SIZE,TYPE,SERIAL,WWN,FSTYPE,UUID,MOUNTPOINTS '" + path + "'\n"
	out, err := r.Run(ctx, script)
	if err != nil {
		return Observation{}, fmt.Errorf("inspect disk: %w", err)
	}
	return Parse(path, out)
}

// Parse validates lsblk's JSON. Missing identity or incomplete data is an
// error: a future writer must never mistake an unknown device for a blank one.
func Parse(requested string, b []byte) (Observation, error) {
	if !byID.MatchString(requested) {
		return Observation{}, fmt.Errorf("invalid stable disk path")
	}
	var doc struct {
		Devices []struct {
			Name        string            `json:"name"`
			MajorMinor  string            `json:"maj:min"`
			Size        uint64            `json:"size"`
			Type        string            `json:"type"`
			Serial      *string           `json:"serial"`
			WWN         *string           `json:"wwn"`
			FSType      *string           `json:"fstype"`
			UUID        *string           `json:"uuid"`
			Mountpoints []*string         `json:"mountpoints"`
			Children    []json.RawMessage `json:"children"`
		} `json:"blockdevices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Devices) != 1 {
		return Observation{}, fmt.Errorf("lsblk returned invalid or ambiguous device data")
	}
	d := doc.Devices[0]
	if !strings.HasPrefix(d.Name, "/dev/") || d.MajorMinor == "" || d.Size == 0 || d.Type == "" {
		return Observation{}, fmt.Errorf("lsblk did not identify the device completely")
	}
	val := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	obs := Observation{Requested: requested, Device: d.Name, MajorMinor: d.MajorMinor, Size: d.Size, Type: d.Type, Serial: val(d.Serial), WWN: val(d.WWN), Filesystem: val(d.FSType), UUID: val(d.UUID)}
	if obs.Serial == "" && obs.WWN == "" {
		return Observation{}, fmt.Errorf("device has no serial number or WWN; cannot safely identify it")
	}
	for _, m := range d.Mountpoints {
		if m != nil && *m != "" {
			obs.Mountpoints = append(obs.Mountpoints, *m)
		}
	}
	// A child tree requires a recursive parser that retains every safety field.
	// Fail closed until partition observations can be evaluated completely.
	if len(d.Children) > 0 {
		return Observation{}, fmt.Errorf("device has child devices; inspect its partitions and mounts before proceeding")
	}
	return obs, nil
}
