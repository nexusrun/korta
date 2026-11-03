// Package cloud provisions infrastructure from approved role steps.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/nexusrun/korta/roles"
	"github.com/nexusrun/korta/sshclient"
)

// EC2 is replaceable in tests. Every call signs in with the credentials of
// one AWS account. Identity, Resolve and States only read.
type EC2 interface {
	Resolve(context.Context, Credentials, Request) (Plan, error)
	Prepare(context.Context, Credentials, Plan, Owner, string, Fleet) (Fleet, error)
	Launch(context.Context, Credentials, roles.AWSInstance, string, string) (string, error)
	Address(context.Context, Credentials, roles.AWSInstance, string, string) (string, error)
}

// Rule allows inbound traffic to a role's instances.
type Rule struct {
	Protocol string   `json:"protocol"` // tcp or udp
	Port     int      `json:"port"`
	CIDRs    []string `json:"cidrs"`
	Groups   []string `json:"groups,omitempty"` // security groups, such as the load balancer's
}

// Network is a preset an admin defines once and roles name: where instances
// go and who may reach them over SSH.
type Network struct {
	Region         string   `json:"region"`
	Subnets        []string `json:"subnets"`                  // public, or all for presets
	PrivateSubnets []string `json:"privateSubnets,omitempty"` // for address: private
	Address        string   `json:"address,omitempty"`        // public (default) or private
	SSHFrom        []string `json:"sshFrom,omitempty"`        // default: the manager's address
	SecurityGroups []string `json:"securityGroups,omitempty"` // attached as well as Korta's
}

// Request asks AWS to complete a role's AWS section.
type Request struct {
	Spec           roles.AWSInstance
	Network        *Network
	KeyFingerprint string // the vault key's, when Spec names its own key pair
	Ingress        []Rule // ports the role's firewall opens, besides SSH
	Account        string // when set, the credentials must still be this account
}

// Plan is a completed AWS section: what an approval launches, exactly.
type Plan struct {
	Account   string            `json:"account"`
	Spec      roles.AWSInstance `json:"spec"` // with region, image, user and address chosen
	ImageName string            `json:"imageName,omitempty"`
	VPC       string            `json:"vpc"`
	Subnets   []string          `json:"subnets"` // instances are spread over these, in order
	// Ingress are the rules of the security group Korta manages for the
	// role, SSH first. It is empty when the role names its own groups.
	Ingress []Rule `json:"ingress,omitempty"`
	// ExtraGroups come from the network and are attached as well.
	ExtraGroups []string `json:"extraGroups,omitempty"`
}

// ManagedGroup reports whether Korta creates the role's security group: it
// does unless the role names its own groups.
func (p Plan) ManagedGroup() bool { return len(p.Spec.SecurityGroups) == 0 }

// ManagedKey reports whether Korta creates the role's SSH key and key pair.
func (p Plan) ManagedKey() bool { return p.Spec.KeyPair == "" }

// Fleet is what Korta created in AWS for one role.
type Fleet struct {
	VPC           string `json:"vpc,omitempty"`
	SecurityGroup string `json:"securityGroup,omitempty"`
	KeyPair       string `json:"keyPair,omitempty"`
}

// Owner names the role that resources belong to, for names and tags.
type Owner struct{ ID, Name string }

func (o Owner) resourceName() string {
	suffix := strings.TrimPrefix(o.ID, "role_")
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	return "korta-" + strings.TrimPrefix(o.Name, "korta-") + "-" + suffix
}

type ec2API interface {
	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	DescribeKeyPairs(context.Context, *ec2.DescribeKeyPairsInput, ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error)
	ImportKeyPair(context.Context, *ec2.ImportKeyPairInput, ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error)
	DeleteKeyPair(context.Context, *ec2.DeleteKeyPairInput, ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error)
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error)
	DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
	DescribeSecurityGroupRules(context.Context, *ec2.DescribeSecurityGroupRulesInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error)
	AuthorizeSecurityGroupIngress(context.Context, *ec2.AuthorizeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(context.Context, *ec2.RevokeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
}

// AWS uses the SDK's standard credential chain on the manager. No SDK error
// message is returned, because credential providers can include secret text.
type AWS struct {
	// connect is replaced in tests.
	connect func(ctx context.Context, cred Credentials, region, expectedAccount string) (ec2API, string, string, error)
	// publicIP returns the manager's public IPv4 address, which SSH rules
	// allow by default. Tests replace it.
	publicIP func(ctx context.Context) (string, error)
}

func (c AWS) conn(ctx context.Context, cred Credentials, region, account string) (ec2API, string, string, error) {
	if c.connect != nil {
		return c.connect(ctx, cred, region, account)
	}
	return connection(ctx, cred, region, account)
}

// connection returns an EC2 client, the account and the region: region when
// set, otherwise the account's default region (or AWS_REGION).
func connection(ctx context.Context, cred Credentials, region, expectedAccount string) (ec2API, string, string, error) {
	cfg, err := awsConfig(ctx, cred, region)
	if err != nil {
		return nil, "", "", err
	}
	if cfg.Region == "" {
		return nil, "", "", fmt.Errorf("no AWS region: set AWS_REGION or region in the role")
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", "", safeError("identify AWS account", err)
	}
	account := aws.ToString(out.Account)
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) {
		return nil, "", "", fmt.Errorf("AWS returned an invalid account ID")
	}
	if expectedAccount != "" && account != expectedAccount {
		return nil, "", "", fmt.Errorf("AWS account changed since planning; restore the original AWS credentials and plan again")
	}
	return ec2.NewFromConfig(cfg), account, cfg.Region, nil
}

func (c AWS) Identity(ctx context.Context, cred Credentials) (string, string, error) {
	_, account, region, err := c.conn(ctx, cred, "", "")
	return account, region, err
}

func launchInput(a roles.AWSInstance, token string, dryRun bool) *ec2.RunInstancesInput {
	in := &ec2.RunInstancesInput{
		ImageId: aws.String(a.Image), InstanceType: types.InstanceType(a.InstanceType),
		MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
		ClientToken: aws.String(token), DryRun: aws.Bool(dryRun),
		MetadataOptions: &types.InstanceMetadataOptionsRequest{HttpTokens: types.HttpTokensStateRequired},
		NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{{
			DeviceIndex: aws.Int32(0), SubnetId: aws.String(a.Subnet), Groups: a.SecurityGroups,
			AssociatePublicIpAddress: aws.Bool(a.Address == "public"), DeleteOnTermination: aws.Bool(true),
		}},
		TagSpecifications: []types.TagSpecification{{ResourceType: types.ResourceTypeInstance, Tags: []types.Tag{
			{Key: aws.String("Name"), Value: aws.String(a.Name)},
			{Key: aws.String("korta:launch"), Value: aws.String(token)},
		}}},
	}
	// The permission check runs before Korta creates the key pair.
	if a.KeyPair != "" {
		in.KeyName = aws.String(a.KeyPair)
	}
	if len(a.SecurityGroups) == 0 {
		in.NetworkInterfaces[0].Groups = nil
	}
	return in
}

// keyFingerprint returns an EC2 key pair's public key fingerprint, or ""
// when the key pair does not exist.
func keyFingerprint(ctx context.Context, c ec2API, name string) (string, error) {
	out, err := c.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{KeyNames: []string{name}, IncludePublicKey: aws.Bool(true)})
	if errorCode(err) == "InvalidKeyPair.NotFound" {
		return "", nil
	}
	if err != nil {
		return "", safeError("check EC2 key pair", err)
	}
	if len(out.KeyPairs) != 1 {
		return "", nil
	}
	// AWS returns the key with its own comment and line ending; the type
	// and key data are what identify it.
	f := strings.Fields(aws.ToString(out.KeyPairs[0].PublicKey))
	if len(f) < 2 {
		return "", fmt.Errorf("EC2 key pair %s has an unreadable public key", name)
	}
	fp, err := sshclient.HostFingerprint(f[0] + " " + f[1])
	if err != nil {
		return "", fmt.Errorf("EC2 key pair %s has an unreadable public key", name)
	}
	return fp, nil
}

func checkKey(ctx context.Context, c ec2API, name, fingerprint string) error {
	fp, err := keyFingerprint(ctx, c, name)
	switch {
	case err != nil:
		return err
	case fp == "":
		return fmt.Errorf("EC2 key pair %s not found in the chosen region", name)
	case fp != fingerprint:
		return fmt.Errorf("EC2 key pair does not match the selected vault SSH key; import the matching private key or select another key pair")
	}
	return nil
}

func (c AWS) Launch(ctx context.Context, cred Credentials, a roles.AWSInstance, token, account string) (string, error) {
	api, _, _, err := c.conn(ctx, cred, a.Region, account)
	if err != nil {
		return "", err
	}
	return recoverOrLaunch(ctx, api, a, token)
}

func recoverOrLaunch(ctx context.Context, c ec2API, a roles.AWSInstance, token string) (string, error) {
	// Recover a launch whose successful response was lost, even on a later
	// retry. Never replace a stopped or terminated instance automatically.
	found, err := c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{Filters: []types.Filter{{Name: aws.String("client-token"), Values: []string{token}}}})
	if err != nil {
		return "", safeError("recover EC2 launch", err)
	}
	ids := []string{}
	for _, res := range found.Reservations {
		for _, inst := range res.Instances {
			if id := aws.ToString(inst.InstanceId); id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("multiple EC2 instances match this launch reservation; inspect them in AWS before retrying")
	}
	if len(ids) == 1 {
		return ids[0], nil
	}
	out, err := c.RunInstances(ctx, launchInput(a, token, false))
	if err != nil {
		return "", safeError("launch EC2 instance", err)
	}
	if len(out.Instances) != 1 || aws.ToString(out.Instances[0].InstanceId) == "" {
		return "", fmt.Errorf("AWS launch returned no instance ID; retry this role to recover the launch")
	}
	return aws.ToString(out.Instances[0].InstanceId), nil
}

func (c AWS) Address(ctx context.Context, cred Credentials, a roles.AWSInstance, id, account string) (string, error) {
	api, _, _, err := c.conn(ctx, cred, a.Region, account)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		out, err := api.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
		if err != nil && errorCode(err) != "InvalidInstanceID.NotFound" {
			return "", safeError("wait for EC2 instance", err)
		}
		if err == nil {
			for _, res := range out.Reservations {
				for _, inst := range res.Instances {
					if inst.State == nil {
						continue
					}
					switch inst.State.Name {
					case types.InstanceStateNameRunning:
						address := aws.ToString(inst.PublicIpAddress)
						if a.Address == "private" {
							address = aws.ToString(inst.PrivateIpAddress)
						}
						if address != "" {
							return address, nil
						}
					case types.InstanceStateNameTerminated, types.InstanceStateNameShuttingDown, types.InstanceStateNameStopped, types.InstanceStateNameStopping:
						return "", fmt.Errorf("EC2 instance is %s; inspect it in AWS before retrying", inst.State.Name)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for EC2 timed out or was cancelled; inspect the instance in AWS and retry the role")
		case <-time.After(3 * time.Second):
		}
	}
}

// errorCode is AWS's error code, or "" for other errors.
func errorCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

var safeCode = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,79}$`)

func safeError(action string, err error) error {
	var api smithy.APIError
	if errors.As(err, &api) && safeCode.MatchString(api.ErrorCode()) {
		code := api.ErrorCode()
		if strings.Contains(code, "Unauthorized") || strings.Contains(code, "AccessDenied") {
			return fmt.Errorf("%s: AWS %s; grant the account's credentials the permissions in docs/aws.md", action, code)
		}
		return fmt.Errorf("%s: AWS %s; check the region, image, subnet, security groups and key pair in AWS", action, code)
	}
	return fmt.Errorf("%s failed; check AWS credentials and network access", action)
}
