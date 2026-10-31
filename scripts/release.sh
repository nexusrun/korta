#!/usr/bin/env bash
# release.sh VERSION [--dry-run] [--yes]
#
# Tags a release of main. It checks that main is clean, matches origin and
# passes make check, writes release notes from the Conventional Commits since
# the last tag, then pushes an annotated tag; CI builds and publishes the
# release from it. --dry-run prints the notes and stops.
set -euo pipefail

version=${1:-}
dry=false yes=false
for arg in "${@:2}"; do
	case $arg in
	--dry-run) dry=true ;;
	--yes) yes=true ;;
	*) echo "unknown option $arg" >&2; exit 2 ;;
	esac
done

fail() { echo "release: $*" >&2; exit 1; }

[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
	fail "give a version such as v0.2.0 or v0.2.0-rc.1"

cd "$(git rev-parse --show-toplevel)"
[[ $(git rev-parse --abbrev-ref HEAD) == main ]] || fail "switch to main first"
[[ -z $(git status --porcelain --untracked-files=no) ]] || fail "commit or stash your changes first"
git fetch --quiet --tags origin main
[[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] || fail "main differs from origin/main; pull or push first"
git rev-parse -q --verify "refs/tags/$version" >/dev/null && fail "$version already exists"

previous=$(git tag --list 'v*' --sort=-v:refname | grep -v -- - | head -1 || true)
if [[ -n $previous && $version != *-* ]]; then
	newest=$(printf '%s\n%s\n' "$previous" "$version" | sort -V | tail -1)
	[[ $newest == "$version" ]] || fail "$version is not newer than $previous"
fi

# A repository can add its own checks, which then run make check itself.
if [[ -x scripts/release-checks.sh ]]; then
	scripts/release-checks.sh || fail "the release checks failed"
else
	make check >/dev/null || fail "make check failed; run it to see why"
fi

notes=$(scripts/release-notes.sh "$previous")
echo "Release $version${previous:+ (since $previous)}"
echo
echo "$notes"
echo
$dry && exit 0
if ! $yes; then
	read -r -p "Tag and push $version? [y/N] " answer
	[[ $answer =~ ^[Yy] ]] || fail "not released"
fi
git tag -a "$version" -m "$version" -m "$notes"
git push origin "$version"
echo "Pushed $version; CI publishes the release: $(git remote get-url origin | sed 's/\.git$//')/actions"
