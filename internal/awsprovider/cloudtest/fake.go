// Package cloudtest provides an in-memory EC2 for tests.
package cloudtest

import (
	"context"
	"fmt"
	"sync"

	"github.com/nexusrun/korta/internal/awsprovider"
	"github.com/nexusrun/korta/roles"
)

const Account = "123456789012"

// Fake resolves a fixed account, region, image and two subnets, and launches
// instances that are running at once. Launching again with a token returns
// the instance that token launched, as EC2 does.
type Fake struct {
	mu        sync.Mutex
	Creds     []cloud.Credentials // used by each call, in order
	Requests  []cloud.Request
	Prepared  []string // public keys Prepare received
	Launched  []roles.AWSInstance
	Tokens    []string
	Destroyed []string
	Networks  int      // networks applied
	Released  []string // static IP allocations released
	Dropped   []string // certificates deleted
	Targets   []string // instances behind the load balancer
	// LBCertificate is the certificate the load balancer was given;
	// Names maps each DNS name to what it points at.
	LBCertificate string
	Names         map[string]string
	LBSubnets     []string          // where the load balancer went
	ids           map[string]string // token to instance ID
	states        map[string]string
	// LaunchErr makes Launch fail, after the instance exists in AWS, as when
	// the response is lost.
	LaunchErr error
}

func (f *Fake) use(c cloud.Credentials) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Creds = append(f.Creds, c)
}

// Identity reaches Account, in the credentials' region or us-east-1.
func (f *Fake) Identity(_ context.Context, c cloud.Credentials) (string, string, error) {
	f.use(c)
	if c.Region != "" {
		return Account, c.Region, nil
	}
	return Account, "us-east-1", nil
}

func (f *Fake) Resolve(_ context.Context, c cloud.Credentials, r cloud.Request) (cloud.Plan, error) {
	f.use(c)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, r)
	if r.Account != "" && r.Account != Account {
		return cloud.Plan{}, fmt.Errorf("AWS account changed")
	}
	spec := r.Spec
	p := cloud.Plan{Account: Account, VPC: "vpc-0000000default", Subnets: []string{"subnet-000000000000a", "subnet-000000000000b"}}
	if n := r.Network; n != nil {
		spec.Region, p.Subnets, p.ExtraGroups, p.VPC = n.Region, n.Subnets, n.SecurityGroups, "vpc-00000000network"
		if spec.Address == "" {
			spec.Address = n.Address
		}
	}
	if spec.Region == "" {
		spec.Region = c.Region
	}
	if spec.Region == "" {
		spec.Region = "us-east-1"
	}
	if spec.Address == "" {
		spec.Address = "public"
	}
	if n := r.Network; n != nil && spec.Address == "private" && len(n.PrivateSubnets) > 0 {
		p.Subnets = n.PrivateSubnets
	}
	if spec.Image == "" {
		spec.Image, p.ImageName = "ami-0123456789abcdef0", "official "+spec.OS
	}
	p.Spec = spec
	if p.ManagedGroup() {
		p.Ingress = append([]cloud.Rule{{Protocol: "tcp", Port: 22, CIDRs: []string{"198.51.100.7/32"}}}, r.Ingress...)
	}
	return p, nil
}

func (f *Fake) Prepare(_ context.Context, c cloud.Credentials, p cloud.Plan, owner cloud.Owner, publicKey string, fl cloud.Fleet) (cloud.Fleet, error) {
	f.use(c)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Prepared = append(f.Prepared, publicKey)
	if p.ManagedKey() {
		if publicKey == "" {
			return fl, fmt.Errorf("no public key for the role's key pair")
		}
		fl.KeyPair = "korta-" + owner.Name
	}
	if p.ManagedGroup() {
		fl.SecurityGroup, fl.VPC = "sg-0000000000000korta", p.VPC
	}
	return fl, nil
}

func (f *Fake) Launch(_ context.Context, c cloud.Credentials, a roles.AWSInstance, token, account string) (string, error) {
	f.use(c)
	f.mu.Lock()
	defer f.mu.Unlock()
	if account != Account {
		return "", fmt.Errorf("wrong account")
	}
	f.Tokens = append(f.Tokens, token)
	if f.ids == nil {
		f.ids, f.states = map[string]string{}, map[string]string{}
	}
	id, ok := f.ids[token]
	if !ok {
		id = fmt.Sprintf("i-%017d", len(f.ids)+1)
		f.ids[token] = id
		f.states[id] = "running"
		f.Launched = append(f.Launched, a)
	}
	if f.LaunchErr != nil {
		return "", f.LaunchErr
	}
	return id, nil
}

func (f *Fake) Address(_ context.Context, c cloud.Credentials, _ roles.AWSInstance, id, _ string) (string, error) {
	f.use(c)
	return "203.0.113." + id[len(id)-1:], nil
}
