package reverseproxy

import (
	"context"
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

func TestUpstreamResolver_ParseAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		wantErr   bool
	}{
		{
			name:      "nil addresses",
			addresses: nil,
			wantErr:   true,
		},
		{
			name:      "empty addresses slice",
			addresses: []string{},
			wantErr:   true,
		},
		{
			name:      "valid single address",
			addresses: []string{"1.1.1.1:53"},
			wantErr:   false,
		},
		{
			name:      "valid multiple addresses",
			addresses: []string{"1.1.1.1:53", "8.8.8.8:53"},
			wantErr:   false,
		},
		{
			name:      "port range address format",
			addresses: []string{"1.1.1.1:53-54"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UpstreamResolver{Addresses: tt.addresses}
			err := u.ParseAddresses()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddresses() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(u.netAddrs) != len(tt.addresses) {
				t.Errorf("ParseAddresses() netAddrs count = %d, want %d", len(u.netAddrs), len(tt.addresses))
			}
		})
	}
}

func TestSRVUpstreams_Provision_Resolver(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// Empty resolver should fail provisioning
	suEmpty := &SRVUpstreams{
		Resolver: &UpstreamResolver{Addresses: []string{}},
	}
	if err := suEmpty.Provision(ctx); err == nil {
		t.Errorf("SRVUpstreams.Provision() expected error for empty resolver addresses, got nil")
	}

	// Valid resolver should succeed provisioning
	suValid := &SRVUpstreams{
		Resolver: &UpstreamResolver{Addresses: []string{"1.1.1.1:53"}},
	}
	if err := suValid.Provision(ctx); err != nil {
		t.Errorf("SRVUpstreams.Provision() unexpected error = %v", err)
	}

	// Test defensive bounds check in dialer function
	if suValid.resolver != nil && suValid.resolver.Dial != nil {
		suValid.Resolver.netAddrs = nil // force empty netAddrs
		_, err := suValid.resolver.Dial(context.Background(), "udp", "1.1.1.1:53")
		if err == nil {
			t.Errorf("SRVUpstreams.resolver.Dial expected error when netAddrs is empty, got nil")
		}
	}
}

func TestAUpstreams_Provision_Resolver(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// Empty resolver should fail provisioning
	auEmpty := &AUpstreams{
		Resolver: &UpstreamResolver{Addresses: []string{}},
	}
	if err := auEmpty.Provision(ctx); err == nil {
		t.Errorf("AUpstreams.Provision() expected error for empty resolver addresses, got nil")
	}

	// Valid resolver should succeed provisioning
	auValid := &AUpstreams{
		Resolver: &UpstreamResolver{Addresses: []string{"1.1.1.1:53"}},
	}
	if err := auValid.Provision(ctx); err != nil {
		t.Errorf("AUpstreams.Provision() unexpected error = %v", err)
	}

	// Test defensive bounds check in dialer function
	if auValid.resolver != nil && auValid.resolver.Dial != nil {
		auValid.Resolver.netAddrs = nil // force empty netAddrs
		_, err := auValid.resolver.Dial(context.Background(), "udp", "1.1.1.1:53")
		if err == nil {
			t.Errorf("AUpstreams.resolver.Dial expected error when netAddrs is empty, got nil")
		}
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
