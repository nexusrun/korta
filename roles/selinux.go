package roles

import (
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

func parseSELinux(it mdItem) ([]Step, error) {
	if len(it.extra) > 0 || it.code != nil {
		return nil, it.errorf("write one SELinux setting per bullet")
	}
	words := strings.Fields(strings.ReplaceAll(it.text, "`", ""))
	if len(words) == 0 {
		return nil, it.errorf("use mode, boolean, port or fcontext")
	}
	var s Step
	switch words[0] {
	case "mode":
		if len(words) != 2 {
			return nil, it.errorf("use mode enforcing or mode permissive")
		}
		s = Step{Type: "selinux-mode", SELinuxMode: words[1]}
	case "boolean":
		if len(words) != 3 || !oneOf(words[2], "on", "off") {
			return nil, it.errorf("use boolean NAME on or off")
		}
		enabled := words[2] == "on"
		s = Step{Type: "selinux-boolean", SELinuxBoolean: words[1], Enabled: &enabled}
	case "port":
		if len(words) != 4 {
			return nil, it.errorf("use port tcp PORT TYPE")
		}
		port, err := strconv.Atoi(words[2])
		if err != nil {
			return nil, it.errorf("port must be a number")
		}
		s = Step{Type: "selinux-port", Protocol: words[1], Port: port, SELinuxType: words[3]}
	case "fcontext":
		if len(words) < 3 || len(words) > 4 || (len(words) == 4 && words[3] != "recursive") {
			return nil, it.errorf("use fcontext PATH TYPE, optionally followed by recursive")
		}
		s = Step{Type: "selinux-fcontext", Path: words[1], SELinuxType: words[2], Recursive: len(words) == 4}
	default:
		return nil, it.errorf("use mode, boolean, port or fcontext")
	}
	if err := s.normalize(); err != nil {
		return nil, it.errorf("%v", err)
	}
	return []Step{s}, nil
}

func init() { template.Must(scripts.Parse(selinuxScripts)) }

// selinuxFileSpec escapes paths as literal SELinux regexes; the optional
// suffix is the only wildcard Korta adds.
func selinuxFileSpec(s Step) string {
	spec := regexp.QuoteMeta(s.Path)
	if s.Recursive {
		spec += "(/.*)?"
	}
	return spec
}

const selinuxScripts = `
{{define "selinux-prelude"}}{{template "prelude"}}export LC_ALL=C
command -v getenforce >/dev/null 2>&1 || { echo 'getenforce is required; install SELinux tools' >&2; exit 1; }
current=$(getenforce)
[ "$current" != Disabled ] || { echo 'SELinux is disabled; enable it and reboot before managing SELinux' >&2; exit 1; }
{{end}}
{{define "selinux-mode"}}{{template "selinux-prelude"}}
command -v setenforce >/dev/null 2>&1 || { echo 'setenforce is required' >&2; exit 1; }
config=/etc/selinux/config
[ -f "$config" ] && [ ! -L "$config" ] || { echo 'SELinux config must be a regular file' >&2; exit 1; }
count=$(awk -F= '/^[[:space:]]*SELINUX[[:space:]]*=/ { n++ } END { print n+0 }' "$config")
[ "$count" = 1 ] || { echo 'SELinux config must contain exactly one SELINUX setting' >&2; exit 1; }
configured=$(awk -F= '/^[[:space:]]*SELINUX[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$config")
case "$current" in Enforcing) runtime=enforcing;; Permissive) runtime=permissive;; *) echo 'unknown SELinux runtime mode' >&2; exit 1;; esac
if [ "$runtime" = '{{.S.SELinuxMode}}' ] && [ "$configured" = '{{.S.SELinuxMode}}' ]; then result ok 'SELinux mode configured'; exit 0; fi
{{if .Apply}}if [ "$configured" != '{{.S.SELinuxMode}}' ]; then
  tmp=$(mktemp /etc/selinux/.xela-config.XXXXXX)
  trap 'rm -f "$tmp"' EXIT
  cp -p "$config" "$tmp"
  awk '/^[[:space:]]*SELINUX[[:space:]]*=/ { print "SELINUX={{.S.SELinuxMode}}"; next } { print }' "$config" > "$tmp"
  mv -f "$tmp" "$config"
  if command -v restorecon >/dev/null 2>&1; then restorecon "$config"; fi
fi
if [ "$runtime" != '{{.S.SELinuxMode}}' ]; then setenforce {{if eq .S.SELinuxMode "enforcing"}}1{{else}}0{{end}}; fi
{{end}}result changed 'SELinux mode configured'
{{end}}
{{define "selinux-boolean"}}{{template "selinux-prelude"}}
for tool in semanage getsebool setsebool; do command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required; install SELinux policy tools" >&2; exit 1; }; done
runtime=$(getsebool '{{.S.SELinuxBoolean}}' | awk '{print $NF}')
[ "$runtime" = on ] || [ "$runtime" = off ] || { echo 'cannot read SELinux boolean' >&2; exit 1; }
listing=$(semanage boolean -l -n)
persistent=$(printf '%s\n' "$listing" | awk -v name='{{.S.SELinuxBoolean}}' '$1==name { gsub(/[(),]/," "); print $3; n++ } END { if(n!=1) exit 1 }') || { echo 'cannot determine persistent SELinux boolean' >&2; exit 1; }
[ "$persistent" = on ] || [ "$persistent" = off ] || { echo 'unrecognized SELinux boolean listing' >&2; exit 1; }
if [ "$runtime" = '{{if deref .S.Enabled}}on{{else}}off{{end}}' ] && [ "$persistent" = '{{if deref .S.Enabled}}on{{else}}off{{end}}' ]; then result ok 'SELinux boolean configured'; exit 0; fi
{{if .Apply}}setsebool -P '{{.S.SELinuxBoolean}}' {{if deref .S.Enabled}}on{{else}}off{{end}}
{{end}}result changed 'SELinux boolean configured'
{{end}}
{{define "selinux-port"}}{{template "selinux-prelude"}}
command -v semanage >/dev/null 2>&1 || { echo 'semanage is required; install SELinux policy tools' >&2; exit 1; }
listing=$(semanage port -l -n)
match=$(printf '%s\n' "$listing" | awk -v proto='{{.S.Protocol}}' -v port='{{.S.Port}}' '
$2==proto { for(i=3;i<=NF;i++) { x=$i; gsub(/,/,"",x); n=split(x,a,"-"); if(n==1 && x==port) { print $1, "single"; count++ } else if(n==2 && port>=a[1] && port<=a[2]) { print $1, "range"; count++ } } }
END { if(count>1) exit 1 }') || { echo 'ambiguous SELinux port mappings' >&2; exit 1; }
if [ "$match" = '{{.S.SELinuxType}} single' ] || [ "$match" = '{{.S.SELinuxType}} range' ]; then result ok 'SELinux port configured'; exit 0; fi
case "$match" in *' range') echo 'port belongs to a different SELinux range; adjust that mapping manually' >&2; exit 1;; esac
{{if .Apply}}if [ -z "$match" ]; then semanage port -a -t '{{.S.SELinuxType}}' -p '{{.S.Protocol}}' '{{.S.Port}}'; else semanage port -m -t '{{.S.SELinuxType}}' -p '{{.S.Protocol}}' '{{.S.Port}}'; fi
{{end}}result changed 'SELinux port configured'
{{end}}
{{define "selinux-fcontext"}}{{template "selinux-prelude"}}
for tool in semanage restorecon matchpathcon; do command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required; install SELinux policy tools" >&2; exit 1; }; done
path='{{.S.Path}}'
[ -e "$path" ] && [ ! -L "$path" ] || { echo 'file context path must exist and not be a symlink' >&2; exit 1; }
spec='{{.Spec}}'
listing=$(semanage fcontext -l -C -n)
localtype=$(printf '%s\n' "$listing" | SPEC="$spec" awk '$1==ENVIRON["SPEC"] { if ($(NF-2)!="all" || $(NF-1)!="files") exit 1; split($NF,a,":"); print a[3]; count++ } END { if(count>1) exit 1 }') || { echo 'ambiguous local SELinux file context' >&2; exit 1; }
changed=no
[ "$localtype" = '{{.S.SELinuxType}}' ] || changed=yes
if [ "$changed" = no ]; then
  effective=$(matchpathcon -n "$path")
  case "$effective" in *:{{.S.SELinuxType}}:*) ;; *) echo 'SELinux file context is shadowed by another rule' >&2; exit 1;; esac
  labels=$(restorecon -n -v {{if .S.Recursive}}-R {{end}}"$path") || { echo 'cannot inspect SELinux file labels' >&2; exit 1; }
  [ -z "$labels" ] || changed=yes
fi
if [ "$changed" = no ]; then result ok 'SELinux file context configured'; exit 0; fi
{{if .Apply}}if [ "$localtype" != '{{.S.SELinuxType}}' ]; then
  if [ -z "$localtype" ]; then semanage fcontext -a -t '{{.S.SELinuxType}}' "$spec"; else semanage fcontext -m -t '{{.S.SELinuxType}}' "$spec"; fi
fi
effective=$(matchpathcon -n "$path")
case "$effective" in *:{{.S.SELinuxType}}:*) ;; *) echo 'SELinux file context is shadowed by another rule' >&2; exit 1;; esac
restorecon {{if .S.Recursive}}-R {{end}}"$path"
{{end}}result changed 'SELinux file context configured'
{{end}}
`
