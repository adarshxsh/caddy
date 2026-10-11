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

func TestUpstreamResolverParseAddresses(t *testing.T) {
	t.Run("empty address list returns error", func(t *testing.T) {
		r := &UpstreamResolver{
			Addresses: []string{},
		}
		err := r.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for empty address list, got nil")
		}

		rNil := &UpstreamResolver{
			Addresses: nil,
		}
		err = rNil.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for nil address list, got nil")
		}
	})

	t.Run("valid address list parses successfully", func(t *testing.T) {
		r := &UpstreamResolver{
			Addresses: []string{"1.1.1.1:53", "8.8.8.8:53"},
		}
		err := r.ParseAddresses()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.netAddrs) != 2 {
			t.Errorf("expected 2 netAddrs, got %d", len(r.netAddrs))
		}
	})

	t.Run("re-parsing resets netAddrs without duplicates", func(t *testing.T) {
		r := &UpstreamResolver{
			Addresses: []string{"1.1.1.1:53"},
		}
		err := r.ParseAddresses()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.netAddrs) != 1 {
			t.Errorf("expected 1 netAddr, got %d", len(r.netAddrs))
		}

		err = r.ParseAddresses()
		if err != nil {
			t.Fatalf("unexpected error on re-parse: %v", err)
		}
		if len(r.netAddrs) != 1 {
			t.Errorf("expected 1 netAddr after re-parse, got %d", len(r.netAddrs))
		}
	})

	t.Run("invalid address returns error", func(t *testing.T) {
		r := &UpstreamResolver{
			Addresses: []string{"1.1.1.1:abc"},
		}
		err := r.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for invalid address, got nil")
		}
	})

	t.Run("port range size greater than 1 returns error", func(t *testing.T) {
		r := &UpstreamResolver{
			Addresses: []string{"1.1.1.1:53-55"},
		}
		err := r.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for port range, got nil")
		}
	})
}

func TestUpstreamsProvisionWithEmptyResolver(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	t.Run("SRVUpstreams with empty resolver", func(t *testing.T) {
		su := &SRVUpstreams{
			Resolver: &UpstreamResolver{
				Addresses: []string{},
			},
		}
		err := su.Provision(ctx)
		if err == nil {
			t.Errorf("expected SRVUpstreams Provision to fail with empty resolver addresses, got nil")
		}
	})

	t.Run("AUpstreams with empty resolver", func(t *testing.T) {
		au := &AUpstreams{
			Resolver: &UpstreamResolver{
				Addresses: []string{},
			},
		}
		err := au.Provision(ctx)
		if err == nil {
			t.Errorf("expected AUpstreams Provision to fail with empty resolver addresses, got nil")
		}
	})

	t.Run("HTTPTransport with empty resolver", func(t *testing.T) {
		ht := &HTTPTransport{
			Resolver: &UpstreamResolver{
				Addresses: []string{},
			},
		}
		err := ht.Provision(ctx)
		if err == nil {
			t.Errorf("expected HTTPTransport Provision to fail with empty resolver addresses, got nil")
		}
	})
}

