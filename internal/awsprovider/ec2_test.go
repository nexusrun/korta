package cloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/nexusrun/korta/roles"
	"golang.org/x/crypto/ssh"
)

// fakeAPI is an in-memory EC2. The embedded interface panics on calls a
// test does not expect.
type fakeAPI struct {
	ec2API
	runInput      *ec2.RunInstancesInput
	describeInput *ec2.DescribeInstancesInput
	found         []types.Instance
	err           error // returned by RunInstances
	runs          int

	arm        bool
	images     []types.Image
	imageQuery *ec2.DescribeImagesInput
	defaultVPC bool
	subnets    []types.Subnet
	keys       map[string]string // key pair name to public key
	groups     int               // security groups created
	rules      map[string]types.SecurityGroupRule
	nextRule   int
	states     map[string]string // instance ID to state
	busy       int               // DeleteSecurityGroup fails this often first
	deleted    []string
}

func apiErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "SECRET-MUST-NOT-LEAK"}
}

func (f *fakeAPI) RunInstances(_ context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.runs++
	f.runInput = in
	return &ec2.RunInstancesOutput{Instances: []types.Instance{{InstanceId: aws.String("i-new")}}}, f.err
}
func (f *fakeAPI) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.describeInput = in
	if f.states == nil {
		return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: f.found}}}, nil
	}
	insts := []types.Instance{}
	for _, id := range in.Filters[0].Values {
		if st, ok := f.states[id]; ok {
			insts = append(insts, types.Instance{InstanceId: aws.String(id), State: &types.InstanceState{Name: types.InstanceStateName(st)}})
			if st == "shutting-down" {
				f.states[id] = "terminated"
			}
		}
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: insts}}}, nil
}
func (f *fakeAPI) TerminateInstances(_ context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	for _, id := range in.InstanceIds {
		f.states[id] = "shutting-down"
	}
	return &ec2.TerminateInstancesOutput{}, nil
}
func (f *fakeAPI) DescribeKeyPairs(_ context.Context, in *ec2.DescribeKeyPairsInput, _ ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	pub, ok := f.keys[in.KeyNames[0]]
	if !ok {
		return nil, apiErr("InvalidKeyPair.NotFound")
	}
	return &ec2.DescribeKeyPairsOutput{KeyPairs: []types.KeyPairInfo{{KeyName: aws.String(in.KeyNames[0]), PublicKey: aws.String(pub)}}}, nil
}
func (f *fakeAPI) ImportKeyPair(_ context.Context, in *ec2.ImportKeyPairInput, _ ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error) {
	f.keys[aws.ToString(in.KeyName)] = string(in.PublicKeyMaterial)
	return &ec2.ImportKeyPairOutput{}, nil
}
func (f *fakeAPI) DeleteKeyPair(_ context.Context, in *ec2.DeleteKeyPairInput, _ ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error) {
	f.deleted = append(f.deleted, aws.ToString(in.KeyName))
	return &ec2.DeleteKeyPairOutput{}, nil
}
func (f *fakeAPI) DescribeInstanceTypes(_ context.Context, in *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	arch := []types.ArchitectureType{types.ArchitectureTypeX8664}
	if f.arm {
		arch = []types.ArchitectureType{types.ArchitectureTypeArm64}
	}
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []types.InstanceTypeInfo{{ProcessorInfo: &types.ProcessorInfo{SupportedArchitectures: arch}}}}, nil
}
func (f *fakeAPI) DescribeImages(_ context.Context, in *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	f.imageQuery = in
	return &ec2.DescribeImagesOutput{Images: f.images}, nil
}
func (f *fakeAPI) DescribeVpcs(_ context.Context, in *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if len(in.VpcIds) > 0 {
		return &ec2.DescribeVpcsOutput{Vpcs: []types.Vpc{{VpcId: aws.String(in.VpcIds[0]), CidrBlock: aws.String("172.31.0.0/16")}}}, nil
	}
	if !f.defaultVPC {
		return &ec2.DescribeVpcsOutput{}, nil
	}
	return &ec2.DescribeVpcsOutput{Vpcs: []types.Vpc{{VpcId: aws.String("vpc-default")}}}, nil
}
func (f *fakeAPI) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	out := []types.Subnet{}
	for _, s := range f.subnets {
		if len(in.SubnetIds) == 0 || strings.Contains(strings.Join(in.SubnetIds, ","), aws.ToString(s.SubnetId)) {
			out = append(out, s)
		}
	}
	return &ec2.DescribeSubnetsOutput{Subnets: out}, nil
}
func (f *fakeAPI) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.groups == 0 {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-korta")}}}, nil
}
func (f *fakeAPI) CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
	f.groups++
	return &ec2.CreateSecurityGroupOutput{GroupId: aws.String("sg-korta")}, nil
}
func (f *fakeAPI) DeleteSecurityGroup(_ context.Context, in *ec2.DeleteSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	if f.busy > 0 {
		f.busy--
		return nil, apiErr("DependencyViolation")
	}
	f.deleted = append(f.deleted, aws.ToString(in.GroupId))
	return &ec2.DeleteSecurityGroupOutput{}, nil
}
func (f *fakeAPI) DescribeSecurityGroupRules(context.Context, *ec2.DescribeSecurityGroupRulesInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error) {
	out := []types.SecurityGroupRule{}
	for _, r := range f.rules {
		out = append(out, r)
	}
	return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: out}, nil
}
func (f *fakeAPI) AuthorizeSecurityGroupIngress(_ context.Context, in *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	for _, p := range in.IpPermissions {
		f.nextRule++
		r := types.SecurityGroupRule{SecurityGroupRuleId: aws.String(fmt.Sprint("sgr-", f.nextRule)), IsEgress: aws.Bool(false), IpProtocol: p.IpProtocol, FromPort: p.FromPort, ToPort: p.ToPort}
		for _, c := range p.IpRanges {
			r.CidrIpv4 = c.CidrIp
		}
		for _, c := range p.Ipv6Ranges {
			r.CidrIpv6 = c.CidrIpv6
		}
		f.rules[aws.ToString(r.SecurityGroupRuleId)] = r
	}
	return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
}
func (f *fakeAPI) RevokeSecurityGroupIngress(_ context.Context, in *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	for _, id := range in.SecurityGroupRuleIds {
		delete(f.rules, id)
	}
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

// cloudWith is an AWS backed by f in us-east-1, reached from 198.51.100.7.
func cloudWith(f *fakeAPI) AWS {
	return AWS{
		connect: func(_ context.Context, _ Credentials, region, _ string) (ec2API, string, string, error) {
			if region == "" {
				region = "us-east-1"
			}
			return f, "123456789012", region, nil
		},
		publicIP: func(context.Context) (string, error) { return "198.51.100.7", nil },
	}
}

func defaultAccount() *fakeAPI {
	f := &fakeAPI{err: apiErr("DryRunOperation"), defaultVPC: true, keys: map[string]string{}, rules: map[string]types.SecurityGroupRule{}}
	f.images = []types.Image{
		{ImageId: aws.String("ami-0000000000000old"), Name: aws.String("ubuntu-noble-old"), CreationDate: aws.String("2026-01-01T00:00:00.000Z")},
		{ImageId: aws.String("ami-0000000000000new"), Name: aws.String("ubuntu-noble-new"), CreationDate: aws.String("2026-09-01T00:00:00.000Z")},
	}
	f.subnets = []types.Subnet{
		{SubnetId: aws.String("subnet-b"), VpcId: aws.String("vpc-default"), AvailabilityZone: aws.String("us-east-1b")},
		{SubnetId: aws.String("subnet-a"), VpcId: aws.String("vpc-default"), AvailabilityZone: aws.String("us-east-1a")},
	}
	return f
}

func minimalSpec(t *testing.T) roles.AWSInstance {
	r := roles.Role{Name: "web", Markdown: "# AWS instance\n- name: web\n- size: t4g.small\n\n# Packages\n- nginx\n"}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	return *r.AWS()
}

func TestResolveChoosesEverything(t *testing.T) {
	f := defaultAccount()
	f.arm = true
	p, err := cloudWith(f).Resolve(context.Background(), Credentials{}, Request{Spec: minimalSpec(t), Ingress: []Rule{{Protocol: "tcp", Port: 443, CIDRs: []string{"::/0", "0.0.0.0/0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	s := p.Spec
	if s.Region != "us-east-1" || s.Image != "ami-0000000000000new" || p.ImageName != "ubuntu-noble-new" || s.User != "ubuntu" || s.Address != "public" || p.Account != "123456789012" {
		t.Fatalf("%+v", p)
	}
	if strings.Join(p.Subnets, ",") != "subnet-a,subnet-b" || p.VPC != "vpc-default" || !p.ManagedGroup() || !p.ManagedKey() {
		t.Fatalf("%+v", p)
	}
	if fmt.Sprint(p.Ingress) != "[{tcp 22 [198.51.100.7/32] []} {tcp 443 [0.0.0.0/0 ::/0] []}]" {
		t.Fatalf("%v", p.Ingress)
	}
	q := f.imageQuery
	if q.Owners[0] != "099720109477" || q.Filters[0].Values[0] != "ubuntu/images/*/ubuntu-noble-24.04-arm64-server-*" || q.Filters[1].Values[0] != "arm64" {
		t.Fatalf("%+v", q)
	}
	// The dry run cannot use the key pair or group that do not exist yet.
	if in := f.runInput; !aws.ToBool(in.DryRun) || in.KeyName != nil || in.NetworkInterfaces[0].Groups != nil || aws.ToString(in.NetworkInterfaces[0].SubnetId) != "subnet-a" {
		t.Fatalf("%+v", in)
	}
}

func TestResolveNetworks(t *testing.T) {
	f := defaultAccount()
	f.defaultVPC = false
	f.subnets = append(f.subnets, types.Subnet{SubnetId: aws.String("subnet-p"), VpcId: aws.String("vpc-prod"), AvailabilityZone: aws.String("eu-west-1a")})
	c := cloudWith(f)
	if _, err := c.Resolve(context.Background(), Credentials{}, Request{Spec: minimalSpec(t)}); err == nil || !strings.Contains(err.Error(), "no default VPC; an admin adds a network") {
		t.Fatal(err)
	}
	prod := &Network{Region: "eu-west-1", Subnets: []string{"subnet-p"}, Address: "private", SecurityGroups: []string{"sg-00000000audit"}}
	p, err := c.Resolve(context.Background(), Credentials{}, Request{Spec: minimalSpec(t), Network: prod})
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.Region != "eu-west-1" || p.Spec.Address != "private" || p.VPC != "vpc-prod" || p.Ingress[0].CIDRs[0] != "172.31.0.0/16" || p.ExtraGroups[0] != "sg-00000000audit" {
		t.Fatalf("%+v", p)
	}
	other := minimalSpec(t)
	other.Region = "us-west-2"
	if _, err := c.Resolve(context.Background(), Credentials{}, Request{Spec: other, Network: prod}); err == nil || !strings.Contains(err.Error(), "differs from its network") {
		t.Fatal(err)
	}
}

func publicKey(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestPrepareCreatesOnceAndSyncsRules(t *testing.T) {
	f := defaultAccount()
	c := cloudWith(f)
	owner := Owner{ID: "role_0123456789abcdef", Name: "web"}
	key := publicKey(t)
	p := Plan{Account: "123456789012", Spec: minimalSpec(t), VPC: "vpc-default", Ingress: []Rule{{Protocol: "tcp", Port: 22, CIDRs: []string{"198.51.100.7/32"}}, {Protocol: "tcp", Port: 80, CIDRs: []string{"0.0.0.0/0"}}}}
	fleet, err := c.Prepare(context.Background(), Credentials{}, p, owner, key, Fleet{})
	if err != nil || fleet.KeyPair != "korta-web-01234567" || fleet.SecurityGroup != "sg-korta" || f.groups != 1 || len(f.rules) != 2 || f.keys["korta-web-01234567"] != key {
		t.Fatalf("%+v %v %d %v", fleet, err, f.groups, f.rules)
	}
	// The role now opens 443 instead of 80: one rule goes, one comes.
	p.Ingress[1].Port = 443
	if _, err := c.Prepare(context.Background(), Credentials{}, p, owner, key, fleet); err != nil || f.groups != 1 || len(f.rules) != 2 {
		t.Fatal(err, f.groups)
	}
	ports := []int32{}
	for _, r := range f.rules {
		ports = append(ports, aws.ToInt32(r.FromPort))
	}
	if fmt.Sprint(ports) != "[22 443]" && fmt.Sprint(ports) != "[443 22]" {
		t.Fatal(ports)
	}
	// AWS describes keys with its own comment and a newline; still the same key.
	f.keys["korta-web-01234567"] = key + " korta-web-01234567\n"
	if _, err := c.Prepare(context.Background(), Credentials{}, p, owner, key, fleet); err != nil {
		t.Fatal("AWS's form of the same key was refused:", err)
	}
	// A key pair with the same name but another key is never overwritten.
	if _, err := c.Prepare(context.Background(), Credentials{}, p, owner, publicKey(t), fleet); err == nil || !strings.Contains(err.Error(), "exists with a different key") {
		t.Fatal(err)
	}
}

func TestImagePatterns(t *testing.T) {
	for os, want := range map[string]string{
		"ubuntu 22.04":     "099720109477 ubuntu/images/*/ubuntu-jammy-22.04-amd64-server-*",
		"debian 13":        "136693071363 debian-13-amd64-*",
		"rhel 9":           "309956199498 RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP*",
		"rocky 9":          "792107900819 Rocky-9-EC2-Base-9.*.x86_64",
		"almalinux 10":     "764336703387 AlmaLinux OS 10.* x86_64",
		"centos-stream 10": "125523088429 CentOS Stream 10 x86_64 *",
	} {
		src, err := imageFor(os)
		if err != nil || src.owner+" "+src.name("x86_64") != want {
			t.Errorf("%s: %s %s %v", os, src.owner, src.name("x86_64"), err)
		}
	}
	if src, _ := imageFor("rocky 9"); src.name("arm64") != "Rocky-9-EC2-Base-9.*.aarch64" {
		t.Error(src.name("arm64"))
	}
}

func TestLaunchRequestAndRecovery(t *testing.T) {
	for _, address := range []string{"public", "private"} {
		t.Run(address, func(t *testing.T) {
			a := roles.AWSInstance{Name: "web", Image: "ami-12345678", InstanceType: "t3.micro", Subnet: "subnet-12345678", SecurityGroups: []string{"sg-12345678"}, KeyPair: "deploy", Address: address}
			c := &fakeAPI{}
			id, err := recoverOrLaunch(context.Background(), c, a, "stable-token")
			if err != nil || id != "i-new" || c.runs != 1 {
				t.Fatalf("%s %v", id, err)
			}
			in := c.runInput
			if aws.ToString(in.ClientToken) != "stable-token" || aws.ToInt32(in.MinCount) != 1 || aws.ToInt32(in.MaxCount) != 1 || aws.ToBool(in.DryRun) || aws.ToString(in.KeyName) != "deploy" {
				t.Fatal("incorrect launch request")
			}
			net := in.NetworkInterfaces[0]
			if aws.ToString(net.SubnetId) != a.Subnet || net.Groups[0] != a.SecurityGroups[0] || aws.ToBool(net.AssociatePublicIpAddress) != (address == "public") || in.MetadataOptions.HttpTokens != types.HttpTokensStateRequired {
				t.Fatalf("%+v", in)
			}
			if aws.ToString(c.describeInput.Filters[0].Name) != "client-token" || c.describeInput.Filters[0].Values[0] != "stable-token" {
				t.Fatal("recovery did not look up the saved token")
			}
			c.found = []types.Instance{{InstanceId: aws.String("i-existing")}}
			id, err = recoverOrLaunch(context.Background(), c, a, "stable-token")
			if err != nil || id != "i-existing" || c.runs != 1 {
				t.Fatal("recovery launched a duplicate")
			}
		})
	}
}

func TestDryRunRequiresAWSConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		wantOK     bool
	}{
		{"allowed", "DryRunOperation", true}, {"denied", "UnauthorizedOperation", false}, {"invalid", "InvalidAMIID.NotFound", false}, {"unexpected-success", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeAPI{}
			if tc.code != "" {
				c.err = apiErr(tc.code)
			}
			err := checkLaunchPermission(context.Background(), c, roles.AWSInstance{})
			if (err == nil) != tc.wantOK || !aws.ToBool(c.runInput.DryRun) {
				t.Fatalf("%v", err)
			}
			if err != nil && strings.Contains(err.Error(), "SECRET-MUST-NOT-LEAK") {
				t.Fatal("AWS error leaked its message")
			}
		})
	}
	if err := safeError("credentials", errors.New("SECRET-MUST-NOT-LEAK")); strings.Contains(err.Error(), "SECRET-MUST-NOT-LEAK") {
		t.Fatal(err)
	}
}

func TestAccountCredentials(t *testing.T) {
	// Keep the machine's own AWS setup out of the test.
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	cfg, err := awsConfig(context.Background(), Credentials{Method: "access-key", AccessKeyID: "AKIAEXAMPLEEXAMPLE12", SecretAccessKey: "secret", Region: "eu-west-1"}, "")
	if err != nil || cfg.Region != "eu-west-1" {
		t.Fatal(err, cfg.Region)
	}
	got, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || got.AccessKeyID != "AKIAEXAMPLEEXAMPLE12" || got.SecretAccessKey != "secret" {
		t.Fatal(err, got.AccessKeyID)
	}
	// A role's or network's region wins over the account's default.
	if cfg, err := awsConfig(context.Background(), Credentials{Method: "assume-role", RoleARN: "arn:aws:iam::123456789012:role/korta", Region: "eu-west-1"}, "us-west-2"); err != nil || cfg.Region != "us-west-2" {
		t.Fatal(err, cfg.Region)
	}
}
