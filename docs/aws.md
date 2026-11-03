# Standalone AWS EC2 roles

Use the core CLI's [AWS role workflow](roles.md#create-aws-instances-from-the-core-cli)
to create and configure EC2 instances. Configure the standard AWS credential
chain and select a region in the role or in AWS configuration. Korta displays
the account and choices before creating resources. AWS charges apply.

The caller needs `sts:GetCallerIdentity` and the EC2 permissions appropriate to
its chosen resources. Planning uses `DescribeImages`, `DescribeInstanceTypes`,
`DescribeVpcs`, `DescribeSubnets`, `DescribeSecurityGroups`, `DescribeKeyPairs`
and an EC2 `RunInstances` dry run. Applying also uses `DescribeInstances`,
`RunInstances`, `ImportKeyPair`, `CreateSecurityGroup`,
`DescribeSecurityGroupRules`, `AuthorizeSecurityGroupIngress` and
`RevokeSecurityGroupIngress`. Creating tagged resources also requires
`ec2:CreateTags`. Prefix these EC2 action names with `ec2:` when writing IAM
policies. Existing security groups avoid managed-group creation. Review IAM
resource restrictions and conditions for your account.

Korta stores launch reservations, a private SSH key and pinned host keys in a
private directory under `$XDG_STATE_HOME/korta/aws`, or
`~/.local/state/korta/aws` by default. Back it up securely. The directory is
keyed by the canonical role file path: moving or renaming the role changes its
identity. Do not delete or recreate the state while AWS resources still exist.
If a run is interrupted, repeat the same command with the same role, AWS account
and state to recover its launch. The CLI does not delete cloud resources.

The first SSH host key is trusted on first use and its fingerprint is printed.
A later key change fails the connection. This initial trust does not establish
identity against an attacker on the network; verify the fingerprint through a
trusted channel when possible. The CLI machine must be able to reach port 22 on
the chosen public or private instance address.

When an AWS role contains firewall steps, Korta uses an active firewalld or UFW
instance. If neither is active, it installs UFW on apt-based hosts when needed,
adds the current SSH peer and the role's open ports, and enables it. Enabling
UFW can change which other ports are reachable. The host plan shows this change
before activation. Korta schedules an automatic UFW disable, checks a new SSH
connection and cancels the rollback only after the check succeeds. A host without
UFW on a non-apt system needs a supported firewall installed first.

The allowed SSH source is the address seen by the host, which may differ from
the caller's public IP for private connections or NAT. If your source address
changes after UFW is enabled, the new address may be blocked before Korta can
connect to update the host firewall. Arrange an additional trusted access path
or update the host's SSH rule before changing networks. AWS security-group
access is also required.
