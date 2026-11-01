package roles

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"text/template"
)

// Host is what step scripts need to know about a target.
type Host struct {
	Family  string // apt or rpm
	Distro  string
	Version string // for {{ os.version }}
	Arch    string // for {{ os.arch }}
	// Planned holds the users ("user:NAME") and groups ("group:NAME") that
	// earlier steps would create. A plan changes nothing, so later steps
	// must not fail because those accounts do not exist yet.
	Planned map[string]bool
}

// Provides reports the accounts a step creates when it changes something.
func (s Step) Provides() []string {
	switch {
	case s.Type == "group" && s.State == "present":
		return []string{"group:" + s.Group}
	case s.Type == "user" && s.State == "present":
		// useradd also creates a group named after the user.
		return []string{"user:" + s.User, "group:" + s.User}
	}
	return nil
}

// Result statuses reported by step scripts.
const (
	StatusOK      = "ok"      // already as desired
	StatusChanged = "changed" // changed (apply) or would change (plan)
	StatusSkipped = "skipped"
	StatusReboot  = "reboot" // changed, and the host is rebooting
)

// Script renders the shell for one step. With apply false it only reports
// what would change. changedBefore tells a service step whether an earlier
// step changed this host, for restartOnChange.
func Script(role string, s Step, h Host, apply, changedBefore bool) (string, error) {
	if s.Type == "patch" && s.Scope == "security" && h.Distro == "centos" {
		return "", fmt.Errorf("CentOS Stream publishes no security advisories; use scope all")
	}
	planned := func(kind, name string) bool { return !apply && h.Planned[kind+":"+name] }
	data := map[string]any{"S": s, "Apply": apply, "Changed": changedBefore, "Family": h.Family, "Role": role,
		"OwnerPlanned": planned("user", s.Owner), "GroupPlanned": planned("group", s.Group), "UserPlanned": planned("user", s.User)}
	switch s.Type {
	case "user":
		missing := []string{}
		for _, g := range s.Groups {
			if !planned("group", g) {
				missing = append(missing, g)
			}
		}
		data["CheckGroups"] = missing
	case "directory":
		data["Mode"] = strings.TrimLeft(s.Mode, "0")
		if data["Mode"] == "" {
			data["Mode"] = "0"
		}
	case "file":
		data["B64"] = base64.StdEncoding.EncodeToString([]byte(s.Content))
		if s.Check != "" {
			data["Check"] = base64.StdEncoding.EncodeToString([]byte(s.Check))
			data["CheckFile"] = strings.Contains(s.Check, "%s")
		}
		data["Mode"] = strings.TrimLeft(s.Mode, "0")
		if data["Mode"] == "" {
			data["Mode"] = "0"
		}
	case "scheduled-job":
		data["JobID"] = fmt.Sprintf("%x", sha256.Sum256([]byte(role+"\x00"+s.Job)))
		command := base64.StdEncoding.EncodeToString([]byte(s.Run))
		line := s.Schedule + " " + s.User + " /bin/sh -c 'echo " + command + " | base64 -d | /bin/sh'\n"
		data["B64"] = base64.StdEncoding.EncodeToString([]byte("# Managed by Xela role " + role + "\n" + line))
	case "command":
		data["B64"] = base64.StdEncoding.EncodeToString([]byte(s.Run))
	case "sysctl":
		keys := make([]string, 0, len(s.Settings))
		for k := range s.Settings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		lines := []string{}
		for _, k := range keys {
			lines = append(lines, k+" = "+s.Settings[k])
		}
		data["Keys"], data["Lines"] = keys, lines
		data["B64"] = base64.StdEncoding.EncodeToString([]byte("# Managed by Xela role " + role + "\n" + strings.Join(lines, "\n") + "\n"))
	}
	if s.Type == "user" {
		data["B64"] = base64.StdEncoding.EncodeToString([]byte(strings.Join(s.AuthorizedKeys, "\n") + "\n"))
	}
	switch s.Type {
	case "firewall":
		rules := []map[string]string{}
		for _, src := range s.Sources {
			family := "ipv4"
			if netip.MustParsePrefix(src).Addr().Is6() {
				family = "ipv6"
			}
			rules = append(rules, map[string]string{"Source": src, "Family": family})
		}
		data["Rules"] = rules
	}
	var b strings.Builder
	if err := scripts.ExecuteTemplate(&b, s.Type, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// ParseResult reads the last KORTA_RESULT line of a step's output.
func ParseResult(out []byte) (status, detail string, ok bool) {
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if rest, found := strings.CutPrefix(line, "KORTA_RESULT "); found {
			status, detail, _ = strings.Cut(rest, " ")
			ok = status == StatusOK || status == StatusChanged || status == StatusSkipped || status == StatusReboot
		}
	}
	return status, strings.TrimSpace(detail), ok
}

var scripts = template.Must(template.New("").Funcs(template.FuncMap{
	"join":  strings.Join,
	"deref": func(b *bool) bool { return b != nil && *b },
}).Parse(`
{{define "prelude"}}set -eu
result() { printf 'KORTA_RESULT %s %s\n' "$1" "$2"; }
{{end}}

{{define "scheduled-job"}}{{template "prelude"}}path='/etc/cron.d/xela-{{.JobID}}'
[ ! -L "$path" ] || { echo "scheduled job path is a symlink; remove it before continuing" >&2; exit 1; }
{{if eq .S.State "absent"}}if [ ! -e "$path" ]; then result ok 'job absent'; exit 0; fi
{{if .Apply}}rm -f -- "$path"{{end}}
result changed 'job removed'
{{else}}[ -d /etc/cron.d ] || { echo "/etc/cron.d is missing; install a cron service first" >&2; exit 1; }
{{if not .UserPlanned}}getent passwd '{{.S.User}}' >/dev/null || { echo 'scheduled job user does not exist' >&2; exit 1; }{{end}}
if [ -f "$path" ] && [ "$(stat -c '%a:%u:%g' "$path")" = 644:0:0 ] && printf '%s' '{{.B64}}' | base64 -d | cmp -s - "$path"; then result ok 'job configured'; exit 0; fi
{{if .Apply}}tmp=$(mktemp /etc/cron.d/.xela-job.XXXXXX)
trap 'rm -f "$tmp"' EXIT
printf '%s' '{{.B64}}' | base64 -d > "$tmp"
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$path"
if command -v restorecon >/dev/null 2>&1; then restorecon "$path"; fi
{{end}}result changed 'job configured'
{{end}}{{end}}

{{define "ntp"}}{{template "prelude"}}command -v timedatectl >/dev/null 2>&1 || { echo "timedatectl is required; use a systemd host" >&2; exit 1; }
current=$(timedatectl show --property=NTP --value)
[ "$current" = yes ] || [ "$current" = no ] || { echo "cannot determine NTP setting on this host" >&2; exit 1; }
if [ "$current" = "{{if deref .S.NTP}}yes{{else}}no{{end}}" ]; then result ok "NTP is {{if deref .S.NTP}}enabled{{else}}disabled{{end}}"; exit 0; fi
{{if .Apply}}timedatectl set-ntp {{if deref .S.NTP}}true{{else}}false{{end}}
result changed "{{if deref .S.NTP}}enabled{{else}}disabled{{end}} NTP"
{{else}}result changed "would {{if deref .S.NTP}}enable{{else}}disable{{end}} NTP"
{{end}}{{end}}

{{define "dns"}}{{template "prelude"}}file=/etc/resolv.conf
[ -f "$file" ] && [ ! -L "$file" ] || { echo "DNS needs a regular /etc/resolv.conf; configure the host's resolver manager instead" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 && systemctl show --property=SystemState --value >/dev/null 2>&1 || { echo "cannot determine active resolver managers; check systemd" >&2; exit 1; }
for service in systemd-resolved NetworkManager resolvconf; do
  if systemctl is-active --quiet "$service"; then echo "$service is active; manage DNS in that service instead" >&2; exit 1; fi
done
current=$(cat "$file")
desired=$(awk '!/^[[:space:]]*nameserver([[:space:]]|$)/ {print}' "$file"; {{range .S.Nameservers}}printf 'nameserver %s\n' '{{.}}'; {{end}}:)
if [ "$current" = "$desired" ]; then result ok "DNS nameservers are configured"; exit 0; fi
{{if .Apply}}tmp=$(mktemp /etc/.xela-resolv.XXXXXXXX)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
printf '%s\n' "$desired" > "$tmp"
chmod --reference="$file" "$tmp"
chown --reference="$file" "$tmp"
[ "$(cat "$file")" = "$current" ] || { echo "resolver configuration changed during apply; plan again" >&2; exit 1; }
mv -f "$tmp" "$file"
if command -v restorecon >/dev/null 2>&1; then restorecon -F "$file" || { echo "DNS file updated, but SELinux relabel failed; restore its context" >&2; exit 1; }; fi
result changed "updated DNS nameservers"
{{else}}result changed "would update DNS nameservers in /etc/resolv.conf"
{{end}}{{end}}

{{define "hostname"}}{{template "prelude"}}command -v hostnamectl >/dev/null 2>&1 || { echo "hostnamectl is required; use a systemd host" >&2; exit 1; }
current=$(hostnamectl --static)
if [ "$current" = "{{.S.Hostname}}" ]; then result ok "hostname is {{.S.Hostname}}"; exit 0; fi
{{if .Apply}}hostnamectl set-hostname "{{.S.Hostname}}"
result changed "set hostname to {{.S.Hostname}}"
{{else}}result changed "would set hostname from $current to {{.S.Hostname}}"
{{end}}{{end}}

{{define "timezone"}}{{template "prelude"}}command -v timedatectl >/dev/null 2>&1 || { echo "timedatectl is required; use a systemd host" >&2; exit 1; }
[ -f "/usr/share/zoneinfo/{{.S.Timezone}}" ] || { echo "timezone is not installed; check the tzdata package" >&2; exit 1; }
current=$(timedatectl show --property=Timezone --value)
if [ "$current" = "{{.S.Timezone}}" ]; then result ok "timezone is {{.S.Timezone}}"; exit 0; fi
{{if .Apply}}timedatectl set-timezone "{{.S.Timezone}}"
result changed "set timezone to {{.S.Timezone}}"
{{else}}result changed "would set timezone from $current to {{.S.Timezone}}"
{{end}}{{end}}

{{define "packages"}}{{template "prelude"}}pkgs="{{join .S.Packages " "}}"
installed() {
{{if eq .Family "apt"}}  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
{{else}}  rpm -q "$1" >/dev/null 2>&1
{{end}}}
todo=""
{{if eq .S.State "absent"}}for p in $pkgs; do installed "$p" && todo="$todo $p"; done
if [ -z "$todo" ]; then result ok "not installed: $pkgs"; exit 0; fi
{{if .Apply}}{{if eq .Family "apt"}}DEBIAN_FRONTEND=noninteractive apt-get remove -y -q $todo{{else}}dnf remove -y $todo{{end}}
result changed "removed$todo"
{{else}}result changed "would remove$todo"
{{end}}{{else}}for p in $pkgs; do installed "$p" || todo="$todo $p"; done
upgrade=""
{{if eq .S.State "latest"}}{{if eq .Family "apt"}}apt-get update -q >/dev/null
for p in $pkgs; do
  installed "$p" || continue
  policy=$(apt-cache policy "$p")
  have=$(echo "$policy" | awk '/Installed:/ {print $2}')
  cand=$(echo "$policy" | awk '/Candidate:/ {print $2}')
  [ "$have" != "$cand" ] && upgrade="$upgrade $p"
done
{{else}}for p in $pkgs; do
  installed "$p" || continue
  rc=0; dnf -q check-update "$p" >/dev/null 2>&1 || rc=$?
  [ "$rc" = 100 ] && upgrade="$upgrade $p"
done
{{end}}{{end}}if [ -z "$todo$upgrade" ]; then result ok "{{if eq .S.State "latest"}}up to date{{else}}installed{{end}}: $pkgs"; exit 0; fi
{{if .Apply}}{{if eq .Family "apt"}}export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
[ -z "$todo" ] || apt-get install -y -q $todo
[ -z "$upgrade" ] || apt-get install -y -q --only-upgrade $upgrade
{{else}}[ -z "$todo" ] || dnf install -y $todo
[ -z "$upgrade" ] || dnf upgrade -y $upgrade
{{end}}result changed "{{if eq .S.State "latest"}}installed:${todo:- none}; upgraded:${upgrade:- none}{{else}}installed$todo{{end}}"
{{else}}result changed "would install:${todo:- none}{{if eq .S.State "latest"}}; would upgrade:${upgrade:- none}{{end}}"
{{end}}{{end}}{{end}}

{{define "patch"}}{{template "prelude"}}{{if eq .Family "apt"}}export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
list=$(apt list --upgradable 2>/dev/null | {{if eq .S.Scope "security"}}grep -E -- '-security' | {{end}}grep '/' | cut -d/ -f1 | sort -u)
{{else}}rc=0
out=$(dnf -q {{if eq .S.Scope "security"}}--security {{end}}check-update{{range .S.Exclude}} --exclude={{.}}{{end}} 2>/dev/null) || rc=$?
[ "$rc" = 0 ] || [ "$rc" = 100 ] || { echo "dnf check-update failed" >&2; exit 1; }
list=$(echo "$out" | awk 'NF == 3 && $1 ~ /\./ {sub(/\.[^.]*$/, "", $1); print $1}' | sort -u)
{{end}}{{range .S.Exclude}}list=$(echo "$list" | grep -vx '{{.}}' || true)
{{end}}count=$(echo "$list" | grep -c . || true)
needs_reboot() {
{{if eq .Family "apt"}}  [ -f /var/run/reboot-required ]
{{else}}  if command -v needs-restarting >/dev/null 2>&1; then ! needs-restarting -r >/dev/null 2>&1; return; fi
  # Without needs-restarting, compare the newest installed kernel with the
  # running one. rpm reports missing packages on stdout, so keep only real
  # package lines; with no kernel package installed, do not reboot.
  newest=$(rpm -q --last kernel-core kernel 2>/dev/null | grep -v 'is not installed' | head -1 | awk '{print $1}' | sed -E 's/^kernel-(core-)?//')
  [ -n "$newest" ] && [ "$newest" != "$(uname -r)" ]
{{end}}}
reboot_now() {
  systemd-run --on-active=3 --timer-property=AccuracySec=100ms /bin/systemctl reboot >/dev/null 2>&1 || (nohup sh -c 'sleep 3; systemctl reboot' >/dev/null 2>&1 &)
}
{{if .Apply}}if [ "$count" -gt 0 ]; then
{{if eq .Family "apt"}}  apt-get install -y -q --only-upgrade -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $list
{{else}}  dnf -y {{if eq .S.Scope "security"}}--security {{end}}upgrade{{range .S.Exclude}} --exclude={{.}}{{end}}
{{end}}fi
{{if eq .S.Reboot "always"}}reboot_now; result reboot "installed $count updates; rebooting"; exit 0
{{else if eq .S.Reboot "if-required"}}if needs_reboot; then reboot_now; result reboot "installed $count updates; rebooting"; exit 0; fi
{{end}}if [ "$count" -gt 0 ]; then result changed "installed $count {{.S.Scope}} updates"; else result ok "no pending {{.S.Scope}} updates"; fi
{{else}}{{if eq .S.Reboot "if-required"}}if needs_reboot; then result changed "$count {{.S.Scope}} updates pending; a reboot is already required and will happen"; exit 0; fi
{{end}}if [ "$count" -gt 0 ]; then result changed "$count {{.S.Scope}} updates pending: $(echo $list | cut -c1-300){{if ne .S.Reboot "never"}}; may reboot{{end}}"
else result {{if eq .S.Reboot "always"}}changed "no pending {{.S.Scope}} updates; would reboot"{{else}}ok "no pending {{.S.Scope}} updates"{{end}}; fi
{{end}}{{end}}

{{define "file"}}{{template "prelude"}}path='{{.S.Path}}'
{{if eq .S.State "absent"}}if [ -d "$path" ]; then echo "$path is a directory; file steps only remove files" >&2; exit 1; fi
if [ ! -e "$path" ]; then result ok "absent"; exit 0; fi
{{if .Apply}}rm -f "$path"; result changed "removed"{{else}}result changed "would remove"{{end}}
{{else}}{{template "owner" .}}want=$(printf '%s' '{{.B64}}' | base64 -d | sha256sum | cut -d' ' -f1)
if [ -d "$path" ]; then echo "$path is a directory" >&2; exit 1; fi
if [ -f "$path" ] && [ "$(sha256sum "$path" | cut -d' ' -f1)" = "$want" ] && [ "$(stat -c '%U %G %a' "$path")" = "{{.S.Owner}} {{.S.Group}} {{.Mode}}" ]; then
  result ok "up to date"; exit 0
fi
what="content or permissions differ"; [ -e "$path" ] || what="missing"
{{if .Apply}}dir=$(dirname "$path")
[ -d "$dir" ] || install -d -m 0755 "$dir"
tmp=$(mktemp "$dir/.xela.XXXXXX")
trap 'rm -f "$tmp"' EXIT
printf '%s' '{{.B64}}' | base64 -d > "$tmp"
chown '{{.S.Owner}}:{{.S.Group}}' "$tmp"
chmod '{{.S.Mode}}' "$tmp"
{{if .Check}}check=$(printf '%s' '{{.Check}}' | base64 -d)
{{if .CheckFile}}# Check the new content before it replaces the old file.
if ! out=$(sh -c "$(printf '%s' "$check" | sed "s#%s#$tmp#g")" 2>&1); then
  printf '%s\n' "$out" | tail -n 20 >&2
  echo "check failed; $path was left unchanged" >&2
  exit 1
fi
mv -f "$tmp" "$path"
{{else}}# Put the new file in place and check it; put the old file back if the check fails.
backup=""
if [ -e "$path" ]; then backup=$(mktemp "$dir/.xela-old.XXXXXX"); cp -p "$path" "$backup"; fi
mv -f "$tmp" "$path"
if ! out=$(sh -c "$check" 2>&1); then
  if [ -n "$backup" ]; then mv -f "$backup" "$path"; else rm -f "$path"; fi
  printf '%s\n' "$out" | tail -n 20 >&2
  echo "check failed; the previous $path was put back" >&2
  exit 1
fi
[ -z "$backup" ] || rm -f "$backup"
{{end}}{{else}}mv -f "$tmp" "$path"
{{end}}trap - EXIT
command -v restorecon >/dev/null 2>&1 && restorecon -F "$path" || true
result changed "written ($what{{if .Check}}; check passed{{end}})"
{{else}}result changed "would write ($what)"
{{end}}{{end}}{{end}}

{{define "owner"}}{{if not .OwnerPlanned}}id -u '{{.S.Owner}}' >/dev/null 2>&1 || { echo "user {{.S.Owner}} does not exist" >&2; exit 1; }
{{end}}{{if not .GroupPlanned}}getent group '{{.S.Group}}' >/dev/null 2>&1 || { echo "group {{.S.Group}} does not exist" >&2; exit 1; }
{{end}}{{end}}

{{define "directory"}}{{template "prelude"}}path='{{.S.Path}}'
{{template "owner" .}}if [ -e "$path" ] && [ ! -d "$path" ]; then echo "$path exists and is not a directory" >&2; exit 1; fi
if [ -d "$path" ] && [ "$(stat -c '%U %G %a' "$path")" = "{{.S.Owner}} {{.S.Group}} {{.Mode}}" ]; then
  result ok "up to date"; exit 0
fi
what="fix owner or mode"; [ -d "$path" ] || what="create"
{{if .Apply}}mkdir -p "$path"
chown '{{.S.Owner}}:{{.S.Group}}' "$path"
chmod '{{.S.Mode}}' "$path"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$path" || true
result changed "done: $what"
{{else}}result changed "would $what"
{{end}}{{end}}

{{define "group"}}{{template "prelude"}}g='{{.S.Group}}'
{{if eq .S.State "absent"}}if ! getent group "$g" >/dev/null 2>&1; then result ok "absent"; exit 0; fi
{{if .Apply}}groupdel "$g"; result changed "removed"{{else}}result changed "would remove"{{end}}
{{else}}if getent group "$g" >/dev/null 2>&1; then result ok "exists"; exit 0; fi
{{if .Apply}}groupadd{{if .S.System}} -r{{end}} "$g"; result changed "created"{{else}}result changed "would create"{{end}}
{{end}}{{end}}

{{define "service"}}{{template "prelude"}}svc='{{.S.Service}}'
{{if and (not .Apply) .Changed}}# A plan installs nothing: an earlier step, such as a package, may provide
# the service.
if ! systemctl cat "$svc" >/dev/null 2>&1; then result changed "would be {{.S.State}} once earlier steps have installed it"; exit 0; fi
{{else}}systemctl cat "$svc" >/dev/null 2>&1 || { echo "service $svc not found" >&2; exit 1; }
{{end}}
# Resolve aliases (sshd is ssh.service on Debian and Ubuntu): systemd refuses
# to enable or disable an alias name.
svc=$(systemctl show -p Id --value "$svc" 2>/dev/null || echo "$svc")
active=$(systemctl is-active "$svc" 2>/dev/null || true)
enabled=$(systemctl is-enabled "$svc" 2>/dev/null || true)
todo=""
{{if eq .S.State "started"}}if [ "$active" != active ]; then todo="$todo start"; {{if and .S.RestartOnChange .Changed}}elif true; then todo="$todo restart"; {{else if and .S.ReloadOnChange .Changed}}elif true; then todo="$todo reload"; {{end}}fi
{{else}}[ "$active" = active ] && todo="$todo stop"
{{end}}{{if .S.Enabled}}{{if deref .S.Enabled}}[ "$enabled" = enabled ] || todo="$todo enable"{{else}}[ "$enabled" = enabled ] && todo="$todo disable"{{end}}
{{end}}if [ -z "$todo" ]; then result ok "$active, $enabled"; exit 0; fi
{{if .Apply}}for action in $todo; do systemctl "$action" "$svc"; done
result changed "$(echo $todo | sed 's/ /, /g')"
{{else}}result changed "would $(echo $todo | sed 's/ /, /g')"
{{end}}{{end}}

{{define "sysctl"}}{{template "prelude"}}file=/etc/sysctl.d/90-xela-{{.Role}}.conf
diff=""
{{range $i, $k := .Keys}}[ "$(sysctl -n '{{$k}}' 2>/dev/null | tr -s '\t ' ' ')" = "$(echo '{{index $.S.Settings $k}}' | tr -s '\t ' ' ')" ] || diff="$diff {{$k}}"
{{end}}same_file=0
want=$(printf '%s' '{{.B64}}' | base64 -d | sha256sum | cut -d' ' -f1)
[ -f "$file" ] && [ "$(sha256sum "$file" | cut -d' ' -f1)" = "$want" ] && same_file=1
if [ -z "$diff" ] && [ "$same_file" = 1 ]; then result ok "settings current"; exit 0; fi
{{if .Apply}}install -d -m 0755 /etc/sysctl.d
printf '%s' '{{.B64}}' | base64 -d > "$file"
chmod 0644 "$file"
sysctl -p "$file" >/dev/null
result changed "applied:${diff:- file only}"
{{else}}result changed "would apply:${diff:- file only}"
{{end}}{{end}}

{{define "user"}}{{template "prelude"}}u='{{.S.User}}'
{{if eq .S.State "absent"}}if ! id -u "$u" >/dev/null 2>&1; then result ok "absent"; exit 0; fi
{{if .Apply}}userdel "$u"; result changed "removed (home directory kept)"{{else}}result changed "would remove (home directory kept)"{{end}}
{{else}}{{range .CheckGroups}}getent group '{{.}}' >/dev/null || { echo "group {{.}} does not exist" >&2; exit 1; }
{{end}}todo=""
if {{if .UserPlanned}}false{{else}}id -u "$u" >/dev/null 2>&1{{end}}; then
{{if .S.Shell}}  [ "$(getent passwd "$u" | cut -d: -f7)" = '{{.S.Shell}}' ] || todo="$todo shell"
{{end}}{{range .S.Groups}}  id -nG "$u" | tr ' ' '\n' | grep -qx '{{.}}' || todo="$todo group:{{.}}"
{{end}}else
  todo=" create"
fi
{{if .S.AuthorizedKeys}}home=$(getent passwd "$u" | cut -d: -f6)
keys_file="${home:-/home/$u}/.ssh/authorized_keys"
want=$(printf '%s' '{{.B64}}' | base64 -d | sha256sum | cut -d' ' -f1)
[ -f "$keys_file" ] && [ "$(sha256sum "$keys_file" | cut -d' ' -f1)" = "$want" ] || todo="$todo keys"
{{end}}if [ -z "$todo" ]; then result ok "up to date"; exit 0; fi
{{if .Apply}}case "$todo" in *create*) useradd -m{{if .S.Shell}} -s '{{.S.Shell}}'{{end}}{{if .S.Groups}} -G '{{join .S.Groups ","}}'{{end}} "$u" ;;
  *) {{if .S.Shell}}usermod -s '{{.S.Shell}}' "$u"; {{end}}{{if .S.Groups}}usermod -a -G '{{join .S.Groups ","}}' "$u";{{end}} : ;; esac
{{if .S.AuthorizedKeys}}home=$(getent passwd "$u" | cut -d: -f6)
install -d -m 0700 -o "$u" -g "$(id -gn "$u")" "$home/.ssh"
printf '%s' '{{.B64}}' | base64 -d > "$home/.ssh/authorized_keys"
chown "$u:$(id -gn "$u")" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
command -v restorecon >/dev/null 2>&1 && restorecon -RF "$home/.ssh" || true
{{end}}result changed "updated:$todo"
{{else}}result changed "would update:$todo"
{{end}}{{end}}{{end}}

{{define "firewall"}}{{template "prelude"}}if systemctl is-active --quiet firewalld 2>/dev/null; then
  todo=0
{{range .Rules}}  rule='rule family={{.Family}} source address={{.Source}} port port={{$.S.Port}} protocol={{$.S.Protocol}} accept'
  if firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then present=1; else present=0; fi
{{if eq $.S.State "open"}}  if [ "$present" = 0 ]; then todo=1; {{if $.Apply}}firewall-cmd --quiet --permanent --add-rich-rule="$rule";{{end}} fi
{{else}}  if [ "$present" = 1 ]; then todo=1; {{if $.Apply}}firewall-cmd --quiet --permanent --remove-rich-rule="$rule";{{end}} fi
{{end}}{{end}}  tool=firewalld
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  todo=0
{{range .Rules}}  if ufw show added 2>/dev/null | grep -Fxq 'ufw allow from {{.Source}} to any port {{$.S.Port}} proto {{$.S.Protocol}}'; then present=1; else present=0; fi
{{if eq $.S.State "open"}}  if [ "$present" = 0 ]; then todo=1; {{if $.Apply}}ufw allow from {{.Source}} to any port {{$.S.Port}} proto {{$.S.Protocol}} >/dev/null;{{end}} fi
{{else}}  if [ "$present" = 1 ]; then todo=1; {{if $.Apply}}ufw delete allow from {{.Source}} to any port {{$.S.Port}} proto {{$.S.Protocol}} >/dev/null;{{end}} fi
{{end}}{{end}}  tool=ufw
else
  result skipped "no active firewall (firewalld or ufw)"; exit 0
fi
if [ "$todo" = 0 ]; then result ok "$tool rules current"; exit 0; fi
{{if .Apply}}[ "$tool" = firewalld ] && firewall-cmd --quiet --reload
result changed "$tool rules updated"
{{else}}result changed "would update $tool rules"
{{end}}{{end}}

{{define "command"}}{{template "prelude"}}{{if .S.Creates}}if [ -e '{{.S.Creates}}' ]; then result skipped "{{.S.Creates}} exists"; exit 0; fi
{{end}}{{if .Apply}}tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s' '{{.B64}}' | base64 -d > "$tmp"
chmod 0700 "$tmp"
sh "$tmp"
result changed "script ran"
{{else}}result changed "would run the custom script"
{{end}}{{end}}
`))
