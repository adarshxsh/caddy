package reverseproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestResolveIpVersion(t *testing.T) {
	falseBool := false
	trueBool := true
	tests := []struct {
		Versions          *IPVersions
		expectedIpVersion string
	}{
		{
			Versions:          &IPVersions{IPv4: &trueBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &falseBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool, IPv4: &falseBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &trueBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool, IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
	}
	for _, test := range tests {
		ipVersion := resolveIpVersion(test.Versions)
		if ipVersion != test.expectedIpVersion {
			t.Errorf("resolveIpVersion(): Expected %s got %s", test.expectedIpVersion, ipVersion)
		}
	}
}

func TestSRVUpstreamsGracePeriod(t *testing.T) {
	su := SRVUpstreams{
		Name:        "example.com",
		Refresh:     caddy.Duration(1 * time.Minute),
		GracePeriod: caddy.Duration(10 * time.Second),
		logger:      zap.NewNop(),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("dns lookup failure")
			},
		},
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	// Populate initial cached entry (stale, older than Refresh)
	suAddr, _, _, _ := su.expandedAddr(req)
	srvsMu.Lock()
	srvs[suAddr] = srvLookup{
		srvUpstreams: su,
		freshness:    time.Now().Add(-2 * time.Minute),
		upstreams:    []Upstream{{Dial: "127.0.0.1:8080"}},
	}
	srvsMu.Unlock()

	defer func() {
		su.ResetCache(nil)
	}()

	upstreams, err := su.GetUpstreams(req)
	if err != nil {
		t.Fatalf("expected GetUpstreams to succeed using cached result, got error: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].Dial != "127.0.0.1:8080" {
		t.Fatalf("unexpected upstreams returned: %v", upstreams)
	}

	srvsMu.RLock()
	cached, ok := srvs[suAddr]
	srvsMu.RUnlock()
	if !ok {
		t.Fatalf("expected cached lookup to exist in srvs map")
	}

	if !cached.isFresh() {
		t.Errorf("expected cached entry to be fresh during GracePeriod, but isFresh() returned false")
	}
}
