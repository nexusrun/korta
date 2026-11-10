package roles

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// A download step installs one file from an HTTPS address: the file itself,
// or one member of a tar or zip archive. The role pins the SHA-256 of what is
// downloaded, so a reviewer approves exact content and a changed upstream
// file is refused.

var (
	checksumRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	memberPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/@+-]{0,250}$`)
	tarSuffixes   = []string{".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst"}
)

// anyArch keys a checksum that holds on every CPU architecture.
const anyArch = "any"

func (s *Step) normalizeDownload() error {
	if s.State == "" {
		s.State = "present"
	}
	if !oneOf(s.State, "present", "absent") {
		return fmt.Errorf("state must be present or absent")
	}
	if err := checkPath(s.Path); err != nil {
		return err
	}
	if strings.HasSuffix(s.Path, "/") {
		return fmt.Errorf("a download needs the file's full path, not a directory")
	}
	if s.State == "absent" {
		if s.URL != "" || len(s.Checksums) > 0 || s.Extract != "" || s.Owner != "" || s.Group != "" || s.Mode != "" {
			return fmt.Errorf("a removed download takes only its path")
		}
		return nil
	}
	if len(s.URL) > 500 || !repositoryURL.MatchString(s.URL) || strings.Contains(s.URL, "$") {
		return fmt.Errorf("the address must be https:// without a user name, password or query, such as https://example.com/tool-1.2.tar.gz")
	}
	if len(s.Checksums) == 0 {
		return fmt.Errorf("sha256 is required: list the checksum the publisher documents, so different content is refused")
	}
	for arch, sum := range s.Checksums {
		if !oneOf(arch, anyArch, "amd64", "arm64") {
			return fmt.Errorf("sha256 is for amd64 or arm64, not %q", arch)
		}
		if arch == anyArch && len(s.Checksums) > 1 {
			return fmt.Errorf("give either one sha256, or sha256 amd64 and sha256 arm64")
		}
		if !checksumRe.MatchString(sum) {
			return fmt.Errorf("sha256 must be 64 hexadecimal characters")
		}
	}
	if s.Extract != "" {
		if !memberPattern.MatchString(s.Extract) || strings.Contains(s.Extract, "..") || strings.Contains(s.Extract, "//") || strings.HasSuffix(s.Extract, "/") {
			return fmt.Errorf("extract names one file inside the archive, such as tool-1.2/bin/tool")
		}
		if !s.zip() && !s.tar() {
			return fmt.Errorf("extract needs an address ending in .zip, %s", strings.Join(tarSuffixes, ", "))
		}
	}
	if s.Owner == "" {
		s.Owner = "root"
	}
	if s.Group == "" {
		s.Group = s.Owner
	}
	if s.Mode == "" {
		s.Mode = "0644"
	}
	if !accountPattern.MatchString(s.Owner) || !accountPattern.MatchString(s.Group) || !modePattern.MatchString(s.Mode) {
		return fmt.Errorf("owner and group must be account names; mode an octal such as 0755")
	}
	return nil
}

func (s Step) zip() bool { return strings.HasSuffix(strings.ToLower(s.URL), ".zip") }

func (s Step) tar() bool {
	for _, suffix := range tarSuffixes {
		if strings.HasSuffix(strings.ToLower(s.URL), suffix) {
			return true
		}
	}
	return false
}

// downloadData picks the checksum for the host's architecture.
func downloadData(s Step, h Host, data map[string]any) error {
	data["ID"] = fmt.Sprintf("%x", sha256.Sum256([]byte(s.Path)))
	if s.State == "absent" {
		return nil
	}
	sum := s.Checksums[h.Arch]
	if sum == "" {
		sum = s.Checksums[anyArch]
	}
	if sum == "" {
		return fmt.Errorf("the role has no sha256 for %s hosts; add - sha256 %s: with that file's checksum", h.Arch, h.Arch)
	}
	data["Sum"], data["Zip"] = sum, s.zip()
	data["Mode"] = strings.TrimLeft(s.Mode, "0")
	if data["Mode"] == "" {
		data["Mode"] = "0"
	}
	return nil
}

func parseDownload(it mdItem) ([]Step, error) {
	s := Step{Type: "download"}
	head := strings.Fields(strings.ReplaceAll(it.text, "`", ""))
	switch {
	case len(head) == 2 && removeWords[strings.ToLower(head[0])]:
		s.Path, s.State = head[1], "absent"
	case len(head) == 3 && strings.EqualFold(head[1], "from"):
		s.Path, s.URL = head[0], head[2]
	default:
		return nil, it.errorf("write a download as - /usr/local/bin/tool from https://example.com/tool, with a sha256 bullet below it; or remove PATH")
	}
	seen := map[string]bool{}
	for _, line := range it.extra {
		key, value, ok := strings.Cut(line, ":")
		key, value = strings.ToLower(strings.Join(strings.Fields(key), " ")), strings.TrimSpace(strings.ReplaceAll(value, "`", ""))
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("write each download field once as field: value, using sha256, extract, owner, group and mode")
		}
		seen[key] = true
		switch key {
		case "sha256", "sha256 amd64", "sha256 arm64":
			if s.Checksums == nil {
				s.Checksums = map[string]string{}
			}
			arch := anyArch
			if f := strings.Fields(key); len(f) == 2 {
				arch = f[1]
			}
			s.Checksums[arch] = strings.ToLower(value)
		case "extract":
			s.Extract = value
		case "owner":
			s.Owner = value
			if owner, group, both := strings.Cut(value, ":"); both {
				if seen["group"] {
					return nil, it.errorf("the group is set twice")
				}
				s.Owner, s.Group = owner, group
			}
		case "group":
			if s.Group != "" {
				return nil, it.errorf("the group is set twice")
			}
			s.Group = value
		case "mode":
			s.Mode = value
		default:
			return nil, it.errorf("unknown download field %q; use sha256, sha256 amd64, sha256 arm64, extract, owner, group and mode", key)
		}
	}
	return []Step{s}, nil
}

func (s Step) downloadMarkdown() string {
	if s.State == "absent" {
		return "- remove " + s.Path + "\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "- %s from %s\n", s.Path, s.URL)
	archs := make([]string, 0, len(s.Checksums))
	for arch := range s.Checksums {
		archs = append(archs, arch)
	}
	sort.Strings(archs)
	for _, arch := range archs {
		if arch == anyArch {
			fmt.Fprintf(&b, "  - sha256: %s\n", s.Checksums[arch])
		} else {
			fmt.Fprintf(&b, "  - sha256 %s: %s\n", arch, s.Checksums[arch])
		}
	}
	if s.Extract != "" {
		fmt.Fprintf(&b, "  - extract: %s\n", s.Extract)
	}
	fmt.Fprintf(&b, "  - owner: %s:%s\n  - mode: %s\n", s.Owner, s.Group, s.Mode)
	return b.String()
}

// A plan never downloads. A plain file is compared with the pinned checksum.
// For an archive member, applying records the archive's checksum, the member
// and the installed file's checksum in a marker, and a plan compares those,
// so a file changed on the host is noticed too. The download lands next to
// its destination and moves into place only after its checksum matches.
var _ = template.Must(scripts.New("download").Parse(`{{template "prelude"}}path='{{.S.Path}}'
marker='/var/lib/xela/downloads/{{.ID}}'
if [ -d "$path" ]; then echo "$path is a directory; a download manages one file" >&2; exit 1; fi
{{if eq .S.State "absent"}}if [ ! -e "$path" ] && [ ! -e "$marker" ]; then result ok "absent"; exit 0; fi
{{if .Apply}}rm -f -- "$path" "$marker"
result changed "removed"
{{else}}result changed "would remove"
{{end}}{{else}}{{template "owner" .}}url='{{.S.URL}}'
want='{{.Sum}}'
have=""
[ ! -f "$path" ] || have=$(sha256sum "$path" | cut -d' ' -f1)
same=0
{{if .S.Extract}}member='{{.S.Extract}}'
if [ -n "$have" ] && [ -f "$marker" ] && [ "$(cat "$marker")" = "$want $member $have" ]; then same=1; fi
{{else}}if [ "$have" = "$want" ]; then same=1; fi
{{end}}if [ "$same" = 1 ]; then
  if [ "$(stat -c '%U %G %a' "$path")" = "{{.S.Owner}} {{.S.Group}} {{.Mode}}" ]; then result ok "up to date"; exit 0; fi
{{if .Apply}}  chown '{{.S.Owner}}:{{.S.Group}}' "$path"
  chmod '{{.S.Mode}}' "$path"
  result changed "fixed owner or mode"; exit 0
{{else}}  result changed "would fix owner or mode"; exit 0
{{end}}fi
missing=""
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing=" curl"
{{if .S.Extract}}command -v {{if .Zip}}unzip{{else}}tar{{end}} >/dev/null 2>&1 || missing="$missing {{if .Zip}}unzip{{else}}tar{{end}}"
{{end}}what="missing"; [ -z "$have" ] || what="content differs"
if [ -n "$missing" ]; then
{{if and (not .Apply) .Changed}}  # A plan installs nothing: an earlier Packages step may provide the tools.
  result changed "would download $url ($what) once earlier steps have installed:$missing"; exit 0
{{else}}  echo "this download needs$missing on the host; list$missing under a Packages heading above this section" >&2; exit 1
{{end}}fi
{{if .Apply}}dir=$(dirname "$path")
[ -d "$dir" ] || install -d -m 0755 "$dir"
tmp=$(mktemp -d "$dir/.xela-dl.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 30 --max-time 1800 -o "$tmp/dl" "$url" || { echo "could not download $url" >&2; exit 1; }
else
  wget -q --https-only -T 60 -O "$tmp/dl" "$url" || { echo "could not download $url" >&2; exit 1; }
fi
got=$(sha256sum "$tmp/dl" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "checksum mismatch: the role lists $want, but $url has $got; nothing was changed" >&2; exit 1; }
{{if .S.Extract}}mkdir "$tmp/x"
if ! {{if .Zip}}unzip -q "$tmp/dl" "$member" -d "$tmp/x"{{else}}tar -xf "$tmp/dl" -C "$tmp/x" -- "$member"{{end}} >/dev/null 2>&1; then
  echo "$member could not be extracted; the archive starts with:" >&2
  { {{if .Zip}}unzip -Z1 "$tmp/dl"{{else}}tar -tf "$tmp/dl"{{end}} 2>&1 || true; } | head -n 20 >&2
  exit 1
fi
src="$tmp/x/$member"
if [ ! -f "$src" ] || [ -L "$src" ]; then echo "$member is not a regular file in the archive" >&2; exit 1; fi
install -d -m 0755 "$(dirname "$marker")"
printf '%s\n' "$want $member $(sha256sum "$src" | cut -d' ' -f1)" > "$tmp/marker"
{{else}}src="$tmp/dl"
{{end}}chown '{{.S.Owner}}:{{.S.Group}}' "$src"
chmod '{{.S.Mode}}' "$src"
mv -f "$src" "$path"
{{if .S.Extract}}mv -f "$tmp/marker" "$marker"
{{else}}rm -f -- "$marker"
{{end}}if command -v restorecon >/dev/null 2>&1; then restorecon -F "$path" || true; fi
result changed "installed from $url ($what; sha256 verified)"
{{else}}result changed "would download $url ($what)"
{{end}}{{end}}`))
