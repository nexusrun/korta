package cloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/nexusrun/korta/roles"
)

const maxGroups = 5 // per network interface

// Resolve completes the section: region, the official image for the OS and
// the instance type's CPU architecture, subnets, address, who may connect
// over SSH and the managed security group's rules. It ends with a dry-run
// launch, so missing permissions show up in the plan.
func (c AWS) Resolve(ctx context.Context, cred Credentials, r Request) (Plan, error) {
	spec, n := r.Spec, r.Network
	if n != nil {
		switch {
		case spec.Region == "":
			spec.Region = n.Region
		case spec.Region != n.Region:
			return Plan{}, fmt.Errorf("the role's region %s differs from its network's region %s; leave region out", spec.Region, n.Region)
		}
		if spec.Address == "" {
			spec.Address = n.Address
		}
		if spec.Address == "" && len(n.Subnets) == 0 {
			spec.Address = "private"
		}
	}
	if spec.Address == "" {
		spec.Address = "public"
	}
	if spec.StaticIP && spec.Address == "private" {
		return Plan{}, fmt.Errorf("static ip gives instances a public address, but the network places them on private addresses; set address: public")
	}
	api, account, region, err := c.conn(ctx, cred, spec.Region, r.Account)
	if err != nil {
		return Plan{}, err
	}
	spec.Region = region
	plan := Plan{Account: account}
	arch, err := architecture(ctx, api, spec.InstanceType)
	if err != nil {
		return Plan{}, err
	}
	if spec.Image == "" {
		if spec.Image, plan.ImageName, err = latestImage(ctx, api, spec.OS, arch); err != nil {
			return Plan{}, err
		}
	} else if plan.ImageName, err = checkImage(ctx, api, spec.Image, arch); err != nil {
		return Plan{}, err
	}
	if plan.Subnets, plan.VPC, err = subnets(ctx, api, spec.Subnet, n, spec.Address, region); err != nil {
		return Plan{}, err
	}
	if spec.KeyPair != "" {
		if err := checkKey(ctx, api, spec.KeyPair, r.KeyFingerprint); err != nil {
			return Plan{}, err
		}
	}
	if n != nil {
		plan.ExtraGroups = n.SecurityGroups
	}
	plan.Spec = spec
	groups := len(spec.SecurityGroups) + len(plan.ExtraGroups)
	if plan.ManagedGroup() {
		groups++
		var ssh []string
		if n != nil {
			ssh = n.SSHFrom
		}
		if len(ssh) == 0 {
			if ssh, err = c.sshSource(ctx, api, spec.Address, plan.VPC); err != nil {
				return Plan{}, err
			}
		}
		plan.Ingress = mergeRules(append([]Rule{{Protocol: "tcp", Port: 22, CIDRs: ssh}}, r.Ingress...))
	}
	if groups > maxGroups {
		return Plan{}, fmt.Errorf("an instance can have at most %d security groups; this role and its network name %d", maxGroups, groups)
	}
	// The managed group and key pair do not exist yet; the dry run checks
	// launching from this image, type and subnet with the other groups.
	dry := spec
	dry.Subnet, dry.SecurityGroups = plan.Subnets[0], append(append([]string{}, spec.SecurityGroups...), plan.ExtraGroups...)
	if err := checkLaunchPermission(ctx, api, dry); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func checkLaunchPermission(ctx context.Context, api ec2API, a roles.AWSInstance) error {
	_, err := api.RunInstances(ctx, launchInput(a, "korta-permission-check", true))
	if errorCode(err) == "DryRunOperation" {
		return nil
	}
	if err == nil {
		return fmt.Errorf("AWS did not confirm a dry run; no launch was requested")
	}
	return safeError("check EC2 launch permissions", err)
}

// architecture is the instance type's CPU architecture: arm64 or x86_64.
func architecture(ctx context.Context, api ec2API, instanceType string) (string, error) {
	out, err := api.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{InstanceTypes: []types.InstanceType{types.InstanceType(instanceType)}})
	if err != nil {
		return "", safeError("check instance type "+instanceType, err)
	}
	if len(out.InstanceTypes) != 1 || out.InstanceTypes[0].ProcessorInfo == nil {
		return "", fmt.Errorf("instance type %s is not offered in this region", instanceType)
	}
	for _, a := range out.InstanceTypes[0].ProcessorInfo.SupportedArchitectures {
		if a == types.ArchitectureTypeArm64 {
			return "arm64", nil
		}
	}
	return "x86_64", nil
}

// latestImage finds the newest official image of os for arch.
func latestImage(ctx context.Context, api ec2API, os, arch string) (string, string, error) {
	src, err := imageFor(os)
	if err != nil {
		return "", "", err
	}
	out, err := api.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{src.owner}, Filters: []types.Filter{
		{Name: aws.String("name"), Values: []string{src.name(arch)}},
		{Name: aws.String("architecture"), Values: []string{arch}},
		{Name: aws.String("state"), Values: []string{"available"}},
	}})
	if err != nil {
		return "", "", safeError("find the "+os+" image", err)
	}
	if len(out.Images) == 0 {
		return "", "", fmt.Errorf("no official %s image for %s in this region; choose another os or set image", os, arch)
	}
	sort.Slice(out.Images, func(i, j int) bool {
		return aws.ToString(out.Images[i].CreationDate) > aws.ToString(out.Images[j].CreationDate)
	})
	return aws.ToString(out.Images[0].ImageId), aws.ToString(out.Images[0].Name), nil
}

// checkImage verifies a role's own image exists and suits the instance type.
func checkImage(ctx context.Context, api ec2API, id, arch string) (string, error) {
	out, err := api.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{id}})
	if err != nil {
		return "", safeError("find image "+id, err)
	}
	if len(out.Images) != 1 {
		return "", fmt.Errorf("image %s was not found in this region", id)
	}
	if got := string(out.Images[0].Architecture); got != arch {
		return "", fmt.Errorf("image %s is %s, but the instance type is %s; choose a matching size or image", id, got, arch)
	}
	return aws.ToString(out.Images[0].Name), nil
}

// subnets returns where instances go and their VPC: the role's subnet, its
// network's subnets, or the default VPC's default subnet in each zone.
func subnets(ctx context.Context, api ec2API, subnet string, n *Network, address, region string) ([]string, string, error) {
	in := &ec2.DescribeSubnetsInput{}
	switch {
	case subnet != "":
		in.SubnetIds = []string{subnet}
	case n != nil && address == "private" && len(n.PrivateSubnets) > 0:
		in.SubnetIds = n.PrivateSubnets
	case n != nil && len(n.Subnets) == 0:
		return nil, "", fmt.Errorf("the network has no public subnets; use address: private")
	case n != nil:
		in.SubnetIds = n.Subnets
	default:
		vpcs, err := api.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{Filters: []types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}}})
		if err != nil {
			return nil, "", safeError("find the default VPC", err)
		}
		if len(vpcs.Vpcs) == 0 {
			return nil, "", fmt.Errorf("%s has no default VPC; an admin adds a network under Settings > AWS, and the role names it with network: NAME", region)
		}
		in.Filters = []types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{aws.ToString(vpcs.Vpcs[0].VpcId)}},
			{Name: aws.String("default-for-az"), Values: []string{"true"}},
		}
	}
	out, err := api.DescribeSubnets(ctx, in)
	if err != nil {
		return nil, "", safeError("find subnets", err)
	}
	if len(out.Subnets) == 0 || len(in.SubnetIds) > 0 && len(out.Subnets) != len(in.SubnetIds) {
		return nil, "", fmt.Errorf("subnets not found in %s; check the role's subnet or its network", region)
	}
	sort.Slice(out.Subnets, func(i, j int) bool {
		return aws.ToString(out.Subnets[i].AvailabilityZone) < aws.ToString(out.Subnets[j].AvailabilityZone)
	})
	ids, vpc := []string{}, aws.ToString(out.Subnets[0].VpcId)
	for _, s := range out.Subnets {
		if aws.ToString(s.VpcId) != vpc {
			return nil, "", fmt.Errorf("a network's subnets must be in one VPC")
		}
		ids = append(ids, aws.ToString(s.SubnetId))
	}
	return ids, vpc, nil
}

// subnetPerZone picks one subnet in each zone, as load balancers need, and
// requires two zones at least.
func subnetPerZone(ctx context.Context, api ec2API, ids []string) ([]string, error) {
	out, err := api.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: ids})
	if err != nil {
		return nil, safeError("read the load balancer's subnets", err)
	}
	byZone := map[string]string{}
	for _, s := range out.Subnets {
		z := aws.ToString(s.AvailabilityZone)
		if byZone[z] == "" || aws.ToString(s.SubnetId) < byZone[z] {
			byZone[z] = aws.ToString(s.SubnetId)
		}
	}
	if len(byZone) < 2 {
		return nil, fmt.Errorf("a load balancer needs subnets in at least two zones; use a network with zones: 2 or more, or the default VPC")
	}
	picked := []string{}
	for _, id := range byZone {
		picked = append(picked, id)
	}
	sort.Strings(picked)
	return picked, nil
}

// sshSource is who may connect over SSH by default: the VPC for private
// addresses, the manager's public address otherwise.
func (c AWS) sshSource(ctx context.Context, api ec2API, address, vpc string) ([]string, error) {
	if address == "private" {
		out, err := api.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{vpc}})
		if err != nil || len(out.Vpcs) != 1 || aws.ToString(out.Vpcs[0].CidrBlock) == "" {
			return nil, fmt.Errorf("could not read VPC %s's address range for the SSH rule; set sshFrom on a network", vpc)
		}
		return []string{aws.ToString(out.Vpcs[0].CidrBlock)}, nil
	}
	find := c.publicIP
	if find == nil {
		find = checkIP
	}
	ip, err := find(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not find the manager's public address for the SSH rule; use address: private, or a network with sshFrom")
	}
	return []string{ip + "/32"}, nil
}

// checkIP asks AWS's checkip service for the manager's public IPv4 address.
func checkIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		return "", err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil || !ip.Is4() {
		return "", fmt.Errorf("unexpected answer")
	}
	return ip.String(), nil
}

// mergeRules combines rules for the same port and protocol, sorted, so a
// plan's rules compare equal however the role lists them.
func mergeRules(rules []Rule) []Rule {
	byKey := map[string]*Rule{}
	keys := []string{}
	for _, r := range rules {
		k := fmt.Sprintf("%s/%05d", r.Protocol, r.Port)
		if byKey[k] == nil {
			byKey[k] = &Rule{Protocol: r.Protocol, Port: r.Port}
			keys = append(keys, k)
		}
		for _, c := range r.CIDRs {
			if !slices.Contains(byKey[k].CIDRs, c) {
				byKey[k].CIDRs = append(byKey[k].CIDRs, c)
			}
		}
	}
	// SSH first, then by port and protocol.
	order := func(k string) string {
		if k == "tcp/00022" {
			return ""
		}
		return k[4:] + k[:3]
	}
	sort.Slice(keys, func(i, j int) bool { return order(keys[i]) < order(keys[j]) })
	out := []Rule{}
	for _, k := range keys {
		sort.Strings(byKey[k].CIDRs)
		out = append(out, *byKey[k])
	}
	return out
}
