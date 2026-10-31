#!/usr/bin/env bash
# dist.sh VERSION
#
# Builds the korta CLI for every supported platform into dist/, as archives
# with checksums.txt.
set -euo pipefail

version=${1:?give the version, such as v0.2.0}
cd "$(git rev-parse --show-toplevel)"
rm -rf dist && mkdir -p dist/work

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for target in $targets; do
	os=${target%/*} arch=${target#*/}
	name="korta_${version#v}_${os}_${arch}"
	dir="dist/work/$name"
	mkdir -p "$dir"
	exe=korta
	[[ $os == windows ]] && exe=korta.exe
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X github.com/nexusrun/korta/cli.Version=$version" \
		-o "$dir/$exe" ./cmd/korta
	cp README.md "$dir/"
	if [[ $os == windows ]]; then
		(cd dist/work && zip -qr "../$name.zip" "$name")
	else
		tar -C dist/work -czf "dist/$name.tar.gz" "$name"
	fi
done
rm -rf dist/work
(cd dist && shasum -a 256 korta_* > checksums.txt)
ls dist
