package cloud

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/nexusrun/korta/sshclient"
)

func (c AWS) Prepare(ctx context.Context, cred Credentials, p Plan, owner Owner, publicKey string, f Fleet) (Fleet, error) {
	api, _, _, err := c.conn(ctx, cred, p.Spec.Region, p.Account)
	if err != nil {
		return f, err
	}
	tags := func(kind types.ResourceType) []types.TagSpecification {
		return []types.TagSpecification{{ResourceType: kind, Tags: []types.Tag{
			{Key: aws.String("Name"), Value: aws.String(owner.resourceName())},
			{Key: aws.String("korta:role"), Value: aws.String(owner.ID)},
		}}}
	}
	if p.ManagedKey() {
		name := owner.resourceName()
		fp, err := keyFingerprint(ctx, api, name)
		switch {
		case err != nil:
			return f, err
		case fp == "":
			if _, err := api.ImportKeyPair(ctx, &ec2.ImportKeyPairInput{KeyName: aws.String(name), PublicKeyMaterial: []byte(publicKey), TagSpecifications: tags(types.ResourceTypeKeyPair)}); err != nil {
				return f, safeError("import the role's key pair", err)
			}
		case fp != fingerprint(publicKey):
			return f, fmt.Errorf("EC2 key pair %s exists with a different key; delete it in AWS, then run the role again", name)
		}
		f.KeyPair = name
	}
	if p.ManagedGroup() {
		if f.SecurityGroup == "" || f.VPC != p.VPC {
			found, err := api.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: []types.Filter{
				{Name: aws.String("tag:korta:role"), Values: []string{owner.ID}},
				{Name: aws.String("vpc-id"), Values: []string{p.VPC}},
			}})
			if err != nil {
				return f, safeError("find the role's security group", err)
			}
			if len(found.SecurityGroups) > 0 {
				f.SecurityGroup = aws.ToString(found.SecurityGroups[0].GroupId)
			} else {
				out, err := api.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{GroupName: aws.String(owner.resourceName()), VpcId: aws.String(p.VPC),
					Description: aws.String("Managed by Korta for role " + owner.Name), TagSpecifications: tags(types.ResourceTypeSecurityGroup)})
				if err != nil {
					return f, safeError("create the role's security group", err)
				}
				f.SecurityGroup = aws.ToString(out.GroupId)
			}
			f.VPC = p.VPC
		}
		rules := p.Ingress
		if err := syncRules(ctx, api, f.SecurityGroup, rules); err != nil {
			return f, err
		}
	}
	return f, nil
}

// ruleKey is one protocol, port and source network.
type ruleKey struct {
	protocol string
	port     int
	cidr     string
}

// syncRules makes the group's inbound rules exactly rules: the group is
// Korta's, so rules removed from the role are revoked.
func syncRules(ctx context.Context, api ec2API, group string, rules []Rule) error {
	out, err := api.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{Filters: []types.Filter{{Name: aws.String("group-id"), Values: []string{group}}}})
	if err != nil {
		return safeError("read the security group's rules", err)
	}
	existing := map[ruleKey]string{}
	for _, r := range out.SecurityGroupRules {
		if aws.ToBool(r.IsEgress) {
			continue
		}
		cidr := aws.ToString(r.CidrIpv4) + aws.ToString(r.CidrIpv6)
		if r.ReferencedGroupInfo != nil {
			cidr = "sg:" + aws.ToString(r.ReferencedGroupInfo.GroupId)
		}
		existing[ruleKey{aws.ToString(r.IpProtocol), int(aws.ToInt32(r.FromPort)), cidr}] = aws.ToString(r.SecurityGroupRuleId)
		if aws.ToInt32(r.FromPort) != aws.ToInt32(r.ToPort) || cidr == "" {
			existing[ruleKey{cidr: "other:" + aws.ToString(r.SecurityGroupRuleId)}] = aws.ToString(r.SecurityGroupRuleId)
		}
	}
	revoke, add := diffRules(existing, rules)
	if len(revoke) > 0 {
		if _, err := api.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{GroupId: aws.String(group), SecurityGroupRuleIds: revoke}); err != nil {
			return safeError("remove security group rules", err)
		}
	}
	for _, k := range add {
		perm := types.IpPermission{IpProtocol: aws.String(k.protocol), FromPort: aws.Int32(int32(k.port)), ToPort: aws.Int32(int32(k.port))}
		if group, ok := strings.CutPrefix(k.cidr, "sg:"); ok {
			perm.UserIdGroupPairs = []types.UserIdGroupPair{{GroupId: aws.String(group), Description: aws.String("Korta load balancer")}}
		} else if netip.MustParsePrefix(k.cidr).Addr().Is4() {
			perm.IpRanges = []types.IpRange{{CidrIp: aws.String(k.cidr), Description: aws.String("Korta")}}
		} else {
			perm.Ipv6Ranges = []types.Ipv6Range{{CidrIpv6: aws.String(k.cidr), Description: aws.String("Korta")}}
		}
		_, err := api.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: aws.String(group), IpPermissions: []types.IpPermission{perm}})
		if err != nil && errorCode(err) != "InvalidPermission.Duplicate" {
			return safeError("add security group rules", err)
		}
	}
	return nil
}

// diffRules returns the rule IDs to revoke and the rules to add so that
// existing (rule to ID) becomes rules.
func diffRules(existing map[ruleKey]string, rules []Rule) (revoke []string, add []ruleKey) {
	want := map[ruleKey]bool{}
	for _, r := range rules {
		sources := append([]string{}, r.CIDRs...)
		for _, g := range r.Groups {
			sources = append(sources, "sg:"+g)
		}
		for _, c := range sources {
			k := ruleKey{r.Protocol, r.Port, c}
			want[k] = true
			if _, ok := existing[k]; !ok {
				add = append(add, k)
			}
		}
	}
	seen := map[string]bool{}
	for k, id := range existing {
		if !want[k] && !seen[id] {
			revoke = append(revoke, id)
			seen[id] = true
		}
	}
	return revoke, add
}

func fingerprint(publicKey string) string {
	fp, _ := sshclient.HostFingerprint(publicKey)
	return fp
}
