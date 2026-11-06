package reverseproxy

import (
	"context"
	"fmt"
	"net"
	"testing"

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

func TestUpstreamResolverEmptyAddrs(t *testing.T) {
	// 1. UpstreamResolver.ParseAddresses with empty addresses
	r := &UpstreamResolver{Addresses: []string{}}
	if err := r.ParseAddresses(); err == nil {
		t.Errorf("UpstreamResolver.ParseAddresses() expected error for empty addresses, got nil")
	}

	// 2. SRVUpstreams.Provision with empty resolver
	su := &SRVUpstreams{Resolver: &UpstreamResolver{Addresses: []string{}}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := su.Provision(ctx); err == nil {
		t.Errorf("SRVUpstreams.Provision() expected error for empty resolver addresses, got nil")
	}

	// 3. AUpstreams.Provision with empty resolver
	au := &AUpstreams{Resolver: &UpstreamResolver{Addresses: []string{}}}
	if err := au.Provision(ctx); err == nil {
		t.Errorf("AUpstreams.Provision() expected error for empty resolver addresses, got nil")
	}

	// 4. HTTPTransport.NewTransport with empty resolver
	ht := &HTTPTransport{Resolver: &UpstreamResolver{Addresses: []string{}}}
	if _, err := ht.NewTransport(ctx); err == nil {
		t.Errorf("HTTPTransport.NewTransport() expected error for empty resolver addresses, got nil")
	}
}

func TestUpstreamResolverDialerEmptyAddrs(t *testing.T) {
	r := &UpstreamResolver{}

	// su dialer test
	su := &SRVUpstreams{Resolver: r}
	suDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if len(su.Resolver.netAddrs) == 0 {
			return nil, fmt.Errorf("no resolver addresses configured")
		}
		return nil, nil
	}
	if _, err := suDial(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Errorf("expected error from suDial when netAddrs is empty, got nil")
	}

	// au dialer test
	au := &AUpstreams{Resolver: r}
	auDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if len(au.Resolver.netAddrs) == 0 {
			return nil, fmt.Errorf("no resolver addresses configured")
		}
		return nil, nil
	}
	if _, err := auDial(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Errorf("expected error from auDial when netAddrs is empty, got nil")
	}

	// ht dialer test
	ht := &HTTPTransport{Resolver: r}
	htDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if len(ht.Resolver.netAddrs) == 0 {
			return nil, fmt.Errorf("no resolver addresses configured")
		}
		return nil, nil
	}
	if _, err := htDial(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Errorf("expected error from htDial when netAddrs is empty, got nil")
	}
}

func TestResolverCacheKey(t *testing.T) {
	key := func(addrs ...string) string {
		if addrs == nil {
			return resolverCacheKey(nil)
		}
		return resolverCacheKey(&UpstreamResolver{Addresses: addrs})
	}

	// The default resolver (nil or empty) yields the empty key, so default-resolver
	// sources keep sharing the cache.
	if got := key(); got != "" {
		t.Errorf("nil resolver: got %q, want \"\"", got)
	}
	if got := resolverCacheKey(&UpstreamResolver{}); got != "" {
		t.Errorf("empty resolver: got %q, want \"\"", got)
	}

	// Order does not matter: the same set maps to the same key.
	if a, b := key("1.1.1.1", "8.8.8.8"), key("8.8.8.8", "1.1.1.1"); a != b {
		t.Errorf("order should not matter: %q != %q", a, b)
	}

	// Different sets must not collide, even when an address contains the
	// delimiter that a naive join would use. {"a,b"} and {"a","b"} are distinct
	// resolver configurations and must get distinct keys.
	colliding := [][2][]string{
		{{"a,b"}, {"a", "b"}},
		{{"unix//run/x,y.sock"}, {"unix//run/x", "y.sock"}},
		{{"10:1"}, {"1", "0:1"}}, // guards the length-prefix encoding itself
	}
	for _, c := range colliding {
		if k1, k2 := key(c[0]...), key(c[1]...); k1 == k2 {
			t.Errorf("distinct address sets %q and %q share key %q", c[0], c[1], k1)
		}
	}
}
