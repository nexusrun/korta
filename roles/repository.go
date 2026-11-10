package roles

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// A repository step adds a third-party package repository and the key that
// signs it, so a later Packages step can install from it. The key is fetched
// over HTTPS and accepted only when its fingerprints are exactly the ones the
// role lists, which is what a reviewer approves.

var (
	repositoryURL   = regexp.MustCompile(`^https://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~%+$/-]*)?$`)
	fingerprintRe   = regexp.MustCompile(`^[0-9A-F]{40}$`)
	suitePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
	componentRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	dnfVariables    = strings.NewReplacer("$releasever", "", "$basearch", "")
	maxFingerprints = 8
)

func (s *Step) normalizeRepository() error {
	if !roleNamePattern.MatchString(s.Repository) {
		return fmt.Errorf("repository needs a lowercase name of at most 63 characters using letters, digits and hyphens")
	}
	if s.State == "" {
		s.State = "present"
	}
	if !oneOf(s.State, "present", "absent") {
		return fmt.Errorf("state must be present or absent")
	}
	if s.State == "absent" {
		if s.URL != "" || s.KeyURL != "" || len(s.Fingerprints) > 0 || s.Suite != "" || len(s.Components) > 0 {
			return fmt.Errorf("a removed repository takes only its name")
		}
		return nil
	}
	s.URL = strings.TrimRight(s.URL, "/")
	if len(s.URL) > 500 || !repositoryURL.MatchString(s.URL) || strings.Contains(dnfVariables.Replace(s.URL), "$") {
		return fmt.Errorf("url must be an https:// address without a user name, password or query, such as https://download.docker.com/linux/ubuntu")
	}
	if len(s.KeyURL) > 500 || !repositoryURL.MatchString(s.KeyURL) || strings.Contains(s.KeyURL, "$") {
		return fmt.Errorf("key must be the https:// address of the repository's signing key")
	}
	if len(s.Fingerprints) == 0 || len(s.Fingerprints) > maxFingerprints {
		return fmt.Errorf("fingerprint is required: list the 1-%d signing key fingerprints the publisher documents, so a different key is refused", maxFingerprints)
	}
	seen := map[string]bool{}
	for i, f := range s.Fingerprints {
		f = strings.ToUpper(strings.Join(strings.Fields(f), ""))
		if !fingerprintRe.MatchString(f) {
			return fmt.Errorf("fingerprint %d must be the full 40 hexadecimal characters, not a short key ID", i+1)
		}
		if seen[f] {
			return fmt.Errorf("fingerprint %s is listed twice", f)
		}
		seen[f] = true
		s.Fingerprints[i] = f
	}
	sort.Strings(s.Fingerprints)
	if s.Suite != "" && !suitePattern.MatchString(s.Suite) {
		return fmt.Errorf("invalid suite %q", s.Suite)
	}
	if len(s.Components) > 8 {
		return fmt.Errorf("a repository takes at most 8 components")
	}
	return all(s.Components, componentRe, "component")
}

// checkRepositoryHost refuses settings that mean nothing on this host's
// package manager, instead of ignoring them.
func checkRepositoryHost(s Step, h Host) error {
	if s.State == "absent" {
		return nil
	}
	if h.Family == "apt" && strings.Contains(s.URL, "$") {
		return fmt.Errorf("$releasever and $basearch are dnf variables; on apt hosts write the address out, with {{ os.version }} if it varies")
	}
	if h.Family == "rpm" && (s.Suite != "" || len(s.Components) > 0) {
		return fmt.Errorf("suite and components are for apt hosts; on dnf hosts put the path in url, such as .../$releasever/$basearch/stable")
	}
	return nil
}

func parseRepository(it mdItem) ([]Step, error) {
	s := Step{Type: "repository"}
	name := strings.Fields(strings.ReplaceAll(it.text, "`", ""))
	switch {
	case len(name) == 2 && removeWords[strings.ToLower(name[0])]:
		s.Repository, s.State = name[1], "absent"
	case len(name) == 1:
		s.Repository = name[0]
	default:
		return nil, it.errorf("write the repository's name on the bullet, such as - docker, with url, key and fingerprint bullets below it; or remove NAME")
	}
	seen := map[string]bool{}
	for _, line := range it.extra {
		key, value, ok := strings.Cut(line, ":")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(strings.ReplaceAll(value, "`", ""))
		if !ok || value == "" || seen[key] {
			return nil, it.errorf("write each repository field once as field: value, using url, key, fingerprint, suite and components")
		}
		seen[key] = true
		switch key {
		case "url":
			s.URL = value
		case "key":
			s.KeyURL = value
		case "fingerprint", "fingerprints":
			for _, f := range strings.Split(value, ",") {
				s.Fingerprints = append(s.Fingerprints, strings.TrimSpace(f))
			}
		case "suite":
			s.Suite = value
		case "components", "component":
			s.Components = strings.Fields(strings.ReplaceAll(value, ",", " "))
		default:
			return nil, it.errorf("unknown repository field %q; use url, key, fingerprint, suite and components", key)
		}
	}
	return []Step{s}, nil
}

func (s Step) repositoryMarkdown() string {
	if s.State == "absent" {
		return "- remove " + s.Repository + "\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "- %s\n  - url: %s\n  - key: %s\n  - fingerprint: %s\n", s.Repository, s.URL, s.KeyURL, strings.Join(s.Fingerprints, ", "))
	if s.Suite != "" {
		fmt.Fprintf(&b, "  - suite: %s\n", s.Suite)
	}
	if len(s.Components) > 0 {
		fmt.Fprintf(&b, "  - components: %s\n", strings.Join(s.Components, ", "))
	}
	return b.String()
}

// The list file records the key's fingerprints, so a plan can tell whether
// the host matches the role without gpg, the network or a temporary file.
// Applying puts both files in place, reads the repository, and puts the
// previous files back if that fails, so a bad repository never stays
// configured.
var _ = template.Must(scripts.New("repository").Parse(`{{template "prelude"}}name='{{.S.Repository}}'
{{if eq .Family "apt"}}list="/etc/apt/sources.list.d/xela-$name.sources"
key="/etc/apt/keyrings/xela-$name.gpg"
{{else}}list="/etc/yum.repos.d/xela-$name.repo"
key="/etc/pki/rpm-gpg/RPM-GPG-KEY-xela-$name"
{{end}}{{if eq .S.State "absent"}}if [ ! -e "$list" ] && [ ! -e "$key" ]; then result ok "absent"; exit 0; fi
{{if .Apply}}rm -f -- "$list" "$key"
result changed "removed"
{{else}}result changed "would remove"
{{end}}{{else}}repo_url='{{.S.URL}}'
key_url='{{.S.KeyURL}}'
want='{{join .S.Fingerprints " "}}'
{{if eq .Family "apt"}}suite='{{.S.Suite}}'
[ -n "$suite" ] || suite=$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")
[ -n "$suite" ] || { echo "cannot tell this host's release codename; set suite on the repository" >&2; exit 1; }
desired=$(printf '%s\n' '# Managed by Xela role {{.Role}}' "# Key: $want" 'Types: deb' "URIs: $repo_url" "Suites: $suite" 'Components: {{if .S.Components}}{{join .S.Components " "}}{{else}}main{{end}}' "Signed-By: $key")
{{else}}desired=$(printf '%s\n' '# Managed by Xela role {{.Role}}' "# Key: $want" "[xela-$name]" "name=xela-$name" "baseurl=$repo_url" 'enabled=1' 'gpgcheck=1' "gpgkey=file://$key")
{{end}}if [ -f "$list" ] && [ -f "$key" ] && [ "$(cat "$list")" = "$desired" ]; then result ok "configured"; exit 0; fi
missing=""
command -v gpg >/dev/null 2>&1 || missing=" {{if eq .Family "apt"}}gnupg{{else}}gnupg2{{end}}"
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing="$missing curl"
if [ -n "$missing" ]; then
{{if and (not .Apply) .Changed}}  # A plan installs nothing: an earlier Packages step may provide the tools.
  result changed "would add $repo_url once earlier steps have installed:$missing"; exit 0
{{else}}  echo "adding a repository needs$missing to fetch and verify its signing key; list$missing under a Packages heading above this section" >&2; exit 1
{{end}}fi
todo="would add"; done="added"
if [ -e "$list" ]; then todo="would update"; done="updated"; fi
{{if .Apply}}tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --proto '=https' --proto-redir '=https' --max-time 120 --max-filesize 1048576 -o "$tmp/key" "$key_url" || { echo "could not download the signing key from $key_url" >&2; exit 1; }
else
  wget -q --https-only -T 120 -O "$tmp/key" "$key_url" || { echo "could not download the signing key from $key_url" >&2; exit 1; }
fi
mkdir -m 0700 "$tmp/gnupg"
gpg --batch --quiet --homedir "$tmp/gnupg" --import "$tmp/key" >/dev/null 2>&1 || { echo "the file at $key_url is not an OpenPGP key" >&2; exit 1; }
got=$(gpg --batch --homedir "$tmp/gnupg" --list-keys --with-colons 2>/dev/null | awk -F: '$1 == "pub" {p = 1} $1 == "fpr" && p {print $10; p = 0}' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
[ "$got" = "$want" ] || { echo "signing key mismatch: the role lists $want, but $key_url has ${got:-no keys}; nothing was changed" >&2; exit 1; }
gpg --batch --homedir "$tmp/gnupg" {{if ne .Family "apt"}}--armor {{end}}--export > "$tmp/key.new"
gpgconf --homedir "$tmp/gnupg" --kill all >/dev/null 2>&1 || true
printf '%s\n' "$desired" > "$tmp/list.new"
put() {
  t=$(mktemp "$(dirname "$2")/.xela.XXXXXX")
  cat "$1" > "$t"
  chmod 0644 "$t"
  mv -f "$t" "$2"
}
install -d -m 0755 "$(dirname "$list")" "$(dirname "$key")"
[ ! -e "$list" ] || cp -p "$list" "$tmp/list.old"
[ ! -e "$key" ] || cp -p "$key" "$tmp/key.old"
put "$tmp/key.new" "$key"
put "$tmp/list.new" "$list"
if command -v restorecon >/dev/null 2>&1; then restorecon -F "$list" "$key" || true; fi
rc=0
{{if eq .Family "apt"}}out=$(apt-get update -q -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any 2>&1) || rc=$?
{{else}}out=$(dnf -q -y makecache --disablerepo='*' --enablerepo="xela-$name" 2>&1) || rc=$?
{{end}}if [ "$rc" != 0 ]; then
  if [ -e "$tmp/list.old" ]; then put "$tmp/list.old" "$list"; else rm -f "$list"; fi
  if [ -e "$tmp/key.old" ]; then put "$tmp/key.old" "$key"; else rm -f "$key"; fi
  printf '%s\n' "$out" | tail -n 20 >&2
  echo "the repository at $repo_url could not be read, so the previous configuration was put back; check url{{if eq .Family "apt"}}, suite and components{{end}}" >&2
  exit 1
fi
result changed "$done $repo_url; signing key verified"
{{else}}result changed "$todo $repo_url"
{{end}}{{end}}`))
