# Contributing to Korta

Thank you for helping. Bug reports, fixes, documentation and new role steps
are all welcome. This guide covers how to propose a change and what makes it
easy to accept.

By taking part you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).
To report a security problem, do not open an issue: follow the
[security policy](SECURITY.md).

## Before you start

- **Bugs:** open an issue with the role or inventory that fails, the command,
  what you expected and what happened. Include `korta version` and the host's
  operating system.
- **Features:** open an issue first, so we can agree on the design before you
  write code. Role syntax is a public format that existing roles depend on, so
  new syntax needs particular care.
- **Small fixes** to code or documentation can go straight to a pull request.

Korta is open core: this repository holds the `korta` CLI and the engine, and
Korta Enterprise, a separate commercial product, adds a manager with a web
console, deployments, an AI assistant, a vault and an audit log. Changes that
belong to those features are out of scope here; if unsure, ask in an issue.

## Set up

You need Go (the version in `.go-version`), `make` and the OpenSSH client.

```sh
git clone https://github.com/nexusrun/korta.git
cd korta
make check   # gofmt, go vet and the tests with the race detector
make build   # writes bin/korta
```

Run your build against a test host with `./bin/korta plan role.md -i hosts.md`.
Use disposable machines or containers for testing, never production hosts.

## Make a change

- **Keep it small and focused.** One pull request solves one problem.
- **Add tests** for every behaviour change, table-driven where it fits, and
  keep `make check` passing.
- **Never guess.** Anything a role or inventory cannot express exactly must be
  an error with its line number, not a best effort.
- **Keep roles compatible.** Roles that work today must keep compiling and
  behave the same.
- **Plans change nothing.** Planning never changes a host; applying always
  needs an explicit approval.
- **Keep secrets out of output.** Secrets, keys and tokens never appear in
  arguments, logs, plans, run logs or errors.
- **Keep host names stable.** Files and services Korta creates on hosts keep
  their `xela` names (`/etc/xela`, `xela-*` units), because existing hosts
  depend on them.
- **Write idiomatic Go:** small files, explicit code, abstractions only when a
  repeated pattern justifies them.
- **Update the docs** when behaviour changes. `docs/` is concise and practical:
  show defaults, explain when to change them, and include a minimal example. Do
  not use em dashes; use commas, colons, parentheses or separate sentences.

## Commits and pull requests

Commit subjects and pull request titles follow
[Conventional Commits](https://www.conventionalcommits.org):
`type(scope): short summary`, where type is one of `feat`, `fix`, `perf`,
`docs`, `refactor`, `test`, `build`, `ci`, `chore` or `revert`, for example
`fix(inventory): accept IPv6 addresses with a port`. Release notes are built
from these subjects. Add `!` for a breaking change, as in `feat(roles)!: ...`.

Every commit must be signed off. Sign-off certifies that you wrote the change,
or otherwise have the right to submit it, under the project's license, as the
[Developer Certificate of Origin](https://developercertificate.org) describes.
Add it with `-s`:

```sh
git commit -s -m "fix(roles): report the line of an unknown service state"
```

This adds `Signed-off-by: Your Name <you@example.com>`, which must match the
commit's author. A check on every pull request verifies it. To sign off
commits you already made:

```sh
git rebase --signoff origin/main
git push --force-with-lease
```

Contributions are licensed under the [Apache License 2.0](LICENSE), like the
rest of Korta.

## Review

A maintainer reviews each pull request. Expect questions: they are about
keeping Korta predictable for everyone who runs it against real servers. Once
CI passes and the review is approved, a maintainer merges it, and the change
ships in the next release.
