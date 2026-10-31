# Releasing

Releases are tags on `main` named by semantic version: `v0.2.0`, or
`v0.2.0-rc.1` for a pre-release. Korta and Korta Enterprise are versioned
independently.

```sh
git switch main && git pull
make release VERSION=v0.2.0          # or scripts/release.sh v0.2.0 --dry-run first
```

The script refuses to tag unless `main` is clean, matches `origin/main`,
passes `make check`, and the version is newer than the last release. It shows
release notes built from the Conventional Commit subjects since the last tag
(`feat`, `fix`, `perf`, `docs`, and `!` for breaking changes), asks, then
pushes an annotated tag carrying those notes.

The Release workflow then runs the checks again, builds `korta` for Linux,
macOS and Windows on amd64 and arm64 (`scripts/dist.sh`), and publishes a
GitHub release with the archives, `checksums.txt` and the notes.
`korta version` in a release prints its version.

After a release that Korta Enterprise needs, update it there:
`go get github.com/nexusrun/korta@v0.2.0`.

CI runs `make check` and a build for every platform on each pull request and
push to `main`.
