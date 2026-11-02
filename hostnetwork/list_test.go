package hostnetwork

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const twoLinks = `[
 {"ifname":"lo","operstate":"UNKNOWN","mtu":65536,"address":"00:00:00:00:00:00","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
 {"ifname":"eth0","operstate":"UP","mtu":9001,"address":"02:11:22:33:44:55","addr_info":[{"local":"10.0.0.5","prefixlen":24},{"local":"fe80::1","prefixlen":64}]}
]`

func TestParseList(t *testing.T) {
	links, err := ParseList([]byte(twoLinks))
	if err != nil || len(links) != 2 {
		t.Fatalf("%+v %v", links, err)
	}
	eth := links[1]
	if eth.Name != "eth0" || eth.State != "UP" || eth.MTU != 9001 || eth.MAC != "02:11:22:33:44:55" || !eth.Inspectable {
		t.Fatalf("%+v", eth)
	}
	if strings.Join(eth.Addresses, ",") != "10.0.0.5/24,fe80::1/64" {
		t.Fatalf("addresses: %v", eth.Addresses)
	}
	if links[0].Addresses[0] != "127.0.0.1/8" {
		t.Fatalf("%+v", links[0])
	}
}

func TestParseListMarksUnusableNames(t *testing.T) {
	links, err := ParseList([]byte(`[{"ifname":"eth0;id","operstate":"UP"}]`))
	if err != nil || len(links) != 1 || links[0].Inspectable {
		t.Fatalf("%+v %v", links, err)
	}
}

func TestParseListRejectsBadOutput(t *testing.T) {
	for _, bad := range []string{`null`, `{}`, `[]x`, `not json`, `[{"operstate":"UP"}]`} {
		if _, err := ParseList([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	links, err := ParseList([]byte(`[]`))
	if err != nil || len(links) != 0 {
		t.Fatalf("empty list: %v %v", links, err)
	}
}

func TestListRunsIPAddressAndReportsFailures(t *testing.T) {
	r := &runner{response: []string{twoLinks}}
	links, err := List(context.Background(), r)
	if err != nil || len(links) != 2 || r.calls[0] != "ip -json address show" {
		t.Fatalf("%+v %v %v", links, err, r.calls)
	}
	r = &runner{err: errors.New("SSH failed")}
	if _, err := List(context.Background(), r); err == nil {
		t.Fatal("ignored failure")
	}
}
