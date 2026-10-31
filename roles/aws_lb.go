package roles

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// AWSLoadBalancer puts an Application Load Balancer in front of a role's
// instances. Korta creates it with its target group, listeners and security
// group, and registers instances as count grows. It can be added, changed
// or removed after the instances exist.
type AWSLoadBalancer struct {
	Listen      string   `json:"listen"`                // http or https
	Certificate string   `json:"certificate,omitempty"` // ACM certificate ARN, for https
	Forward     int      `json:"forward"`               // the instances' port
	HealthCheck string   `json:"healthCheck"`           // path answered with 200-399
	From        []string `json:"from"`                  // networks that may reach it
	Internal    bool     `json:"internal,omitempty"`    // only reachable inside the VPC
}

var (
	certARN    = regexp.MustCompile(`^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f-]{36}$`)
	healthPath = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$`) // up to 1024 long
)

func (lb *AWSLoadBalancer) normalize() error {
	if lb.Listen == "" {
		lb.Listen = "http"
		if lb.Certificate != "" {
			lb.Listen = "https"
		}
	}
	switch {
	case lb.Listen != "http" && lb.Listen != "https":
		return fmt.Errorf("load balancer listen is http or https")
	case lb.Listen == "https" && !certARN.MatchString(lb.Certificate):
		return fmt.Errorf("https needs certificate: the ARN of an ACM certificate in the instances' region, such as arn:aws:acm:us-east-1:123456789012:certificate/…")
	case lb.Listen == "http" && lb.Certificate != "":
		return fmt.Errorf("a certificate needs listen: https")
	}
	if lb.Forward == 0 {
		lb.Forward = 80
	}
	if lb.Forward < 1 || lb.Forward > 65535 {
		return fmt.Errorf("load balancer forward is the instances' port, 1 to 65535")
	}
	if lb.HealthCheck == "" {
		lb.HealthCheck = "/"
	}
	if len(lb.HealthCheck) > 1024 || !healthPath.MatchString(lb.HealthCheck) {
		return fmt.Errorf("health check is a path such as /health")
	}
	if len(lb.From) == 0 {
		lb.From = []string{"0.0.0.0/0"}
	}
	for i, c := range lb.From {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("load balancer from %q must be an IPv4 network such as 0.0.0.0/0", c)
		}
		lb.From[i] = p.Masked().String()
	}
	return nil
}

// Ports are the load balancer's listener ports: 443 and 80 (which
// redirects) for https, 80 for http.
func (lb AWSLoadBalancer) Ports() []int {
	if lb.Listen == "https" {
		return []int{443, 80}
	}
	return []int{80}
}

// parseAWSLoadBalancer reads the "# AWS load balancer" section into the
// AWS instance it belongs to.
func parseAWSLoadBalancer(items []mdItem, a *AWSInstance) error {
	seen := map[string]bool{}
	configured := false // host configuration started
	for _, it := range items {
		switch it.kind {
		case "aws-instance", "vars":
			continue
		case "aws-lb":
		default:
			configured = true
			continue
		}
		if a == nil {
			return it.errorf("an AWS load balancer belongs to a role with an AWS instance section")
		}
		if configured {
			return it.errorf("put the AWS load balancer section right after AWS instance")
		}
		if a.LoadBalancer == nil {
			a.LoadBalancer = &AWSLoadBalancer{}
		}
		lb := a.LoadBalancer
		if it.code != nil || len(it.extra) > 0 {
			return it.errorf("load balancer settings use one flat bullet per field")
		}
		key, value, ok := strings.Cut(it.text, ":")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.Trim(strings.TrimSpace(value), "`")
		if !ok || value == "" || seen[key] {
			return it.errorf("load balancer settings need unique field: value bullets")
		}
		if strings.ContainsAny(value, "{}$\n\r\x00") {
			return it.errorf("load balancer settings must be literal values, without variables or secrets")
		}
		seen[key] = true
		switch key {
		case "listen":
			lb.Listen = strings.ToLower(value)
		case "certificate":
			lb.Certificate = value
		case "forward", "port":
			n, err := strconv.Atoi(value)
			if err != nil {
				return it.errorf("forward must be a port number")
			}
			lb.Forward = n
		case "health check":
			lb.HealthCheck = value
		case "from":
			lb.From = strings.Fields(strings.ReplaceAll(value, ",", " "))
		case "internal":
			switch strings.ToLower(value) {
			case "yes", "true":
				lb.Internal = true
			case "no", "false":
			default:
				return it.errorf("internal is yes or no")
			}
		default:
			return it.errorf("unknown load balancer field; use listen, certificate, forward, health check, from or internal")
		}
	}
	if a != nil && a.LoadBalancer != nil {
		if err := a.LoadBalancer.normalize(); err != nil {
			return fmt.Errorf("AWS load balancer: %w", err)
		}
	}
	return nil
}

func (lb AWSLoadBalancer) markdown() string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "- listen: %s\n", lb.Listen)
	if lb.Certificate != "" {
		fmt.Fprintf(b, "- certificate: %s\n", lb.Certificate)
	}
	fmt.Fprintf(b, "- forward: %d\n- health check: %s\n- from: %s\n", lb.Forward, lb.HealthCheck, strings.Join(lb.From, ", "))
	if lb.Internal {
		b.WriteString("- internal: yes\n")
	}
	return b.String()
}
