package roles

import (
	"fmt"
	"regexp"
	"strings"
)

// dnsName is a hostname with two or more labels; the first may be "*".
var dnsName = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

const maxDNSNames = 20

func normalizeDNS(names []string) ([]string, error) {
	if len(names) > maxDNSNames {
		return nil, fmt.Errorf("list at most %d DNS names", maxDNSNames)
	}
	out := []string{}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if len(n) > 253 || !dnsName.MatchString(n) {
			return nil, fmt.Errorf("%q is not a DNS name such as web.example.com", n)
		}
		for _, o := range out {
			if o == n {
				return nil, fmt.Errorf("DNS name %s is listed twice", n)
			}
		}
		out = append(out, n)
	}
	return out, nil
}

// parseAWSDNS reads the "# AWS DNS" section, one name per bullet, into the
// AWS instance it belongs to. Like the load balancer, it comes before host
// configuration and can change after launch.
func parseAWSDNS(items []mdItem, a *AWSInstance) error {
	configured := false
	for _, it := range items {
		switch it.kind {
		case "aws-instance", "aws-lb", "vars":
			continue
		case "aws-dns":
		default:
			configured = true
			continue
		}
		if a == nil {
			return it.errorf("AWS DNS names belong to a role with an AWS instance section")
		}
		if configured {
			return it.errorf("put the AWS DNS section right after AWS instance and its load balancer")
		}
		if it.code != nil || len(it.extra) > 0 || strings.ContainsAny(it.text, "{}$ :") {
			return it.errorf("list one literal DNS name per bullet, such as - web.example.com")
		}
		a.DNS = append(a.DNS, it.text)
	}
	return nil
}
