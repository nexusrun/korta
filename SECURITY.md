# Security policy

Korta runs commands as root on your servers, so we take security reports
seriously.

## Report a vulnerability

Please do not report security problems in public issues, pull requests or
discussions. Report them privately through
[GitHub's private vulnerability reporting](https://github.com/nexusrun/korta/security/advisories/new),
and include:

- the version (`korta version`) and the affected command or role step;
- how to reproduce it, ideally with a minimal role and inventory;
- what an attacker could do with it.

We acknowledge reports within three working days, keep you informed while we
fix the problem, and credit you in the advisory unless you prefer otherwise.
Please give us a reasonable time to release a fix before disclosing it.

## Supported versions

Security fixes go into the latest release. Upgrade to it to receive them.

## In scope

Problems in this repository: the `korta` CLI, role parsing and the scripts it
runs on hosts, inventory handling and SSH connections. Examples are secrets
appearing in output or logs, a plan that changes a host, host key checks
being bypassed, or role content escaping into unintended commands.
