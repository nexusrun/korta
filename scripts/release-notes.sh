#!/usr/bin/env bash
# release-notes.sh [PREVIOUS_TAG]
#
# Prints Markdown release notes from the Conventional Commit subjects since
# PREVIOUS_TAG (or all of history), grouped by type.
set -euo pipefail

range=HEAD
[[ -n ${1:-} ]] && range="$1..HEAD"

section() {
	local title=$1 pattern=$2 lines
	lines=$(git log --no-merges --format='%s' "$range" | grep -E "$pattern" |
		sed -E 's/^[a-z]+(\([^)]*\))?!?: //; s/^/- /' || true)
	[[ -n $lines ]] && printf '### %s\n\n%s\n\n' "$title" "$lines"
	return 0
}

{
	section "Breaking changes" '^[a-z]+(\([^)]*\))?!: '
	section "Features" '^feat(\([^)]*\))?: '
	section "Fixes" '^fix(\([^)]*\))?: '
	section "Performance" '^perf(\([^)]*\))?: '
	section "Documentation" '^docs(\([^)]*\))?: '
}
