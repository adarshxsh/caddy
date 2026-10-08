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

func TestUpstreamResolverParseAddresses(t *testing.T) {
	t.Run("empty address slice", func(t *testing.T) {
		r := &UpstreamResolver{Addresses: []string{}}
		err := r.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for empty address slice, got nil")
		}
	})

	t.Run("nil address slice", func(t *testing.T) {
		r := &UpstreamResolver{Addresses: nil}
		err := r.ParseAddresses()
		if err == nil {
			t.Errorf("expected error for nil address slice, got nil")
		}
	})

	t.Run("valid address slice resets netAddrs", func(t *testing.T) {
		r := &UpstreamResolver{Addresses: []string{"1.2.3.4:53"}}
		err := r.ParseAddresses()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.netAddrs) != 1 {
			t.Fatalf("expected 1 netAddr, got %d", len(r.netAddrs))
		}

		// Calling ParseAddresses again should reset netAddrs
		err = r.ParseAddresses()
		if err != nil {
			t.Fatalf("unexpected error on second parse: %v", err)
		}
		if len(r.netAddrs) != 1 {
			t.Fatalf("expected netAddrs to be reset to 1 item, got %d", len(r.netAddrs))
		}
	})
}

func TestEmptyResolverAddressesHandling(t *testing.T) {
	ctx := context.Background()

	t.Run("SRVUpstreams Provision with empty resolver addresses", func(t *testing.T) {
		su := &SRVUpstreams{
			Resolver: &UpstreamResolver{Addresses: []string{}},
		}
		err := su.Provision(caddy.Context{})
		if err == nil {
			t.Errorf("expected error during Provision with empty resolver addresses, got nil")
		}
	})

	t.Run("AUpstreams Provision with empty resolver addresses", func(t *testing.T) {
		au := &AUpstreams{
			Resolver: &UpstreamResolver{Addresses: []string{}},
		}
		err := au.Provision(caddy.Context{})
		if err == nil {
			t.Errorf("expected error during Provision with empty resolver addresses, got nil")
		}
	})

	t.Run("HTTPTransport NewTransport with empty resolver addresses", func(t *testing.T) {
		ht := &HTTPTransport{
			Resolver: &UpstreamResolver{Addresses: []string{}},
		}
		_, err := ht.NewTransport(caddy.Context{})
		if err == nil {
			t.Errorf("expected error during NewTransport with empty resolver addresses, got nil")
		}
	})

	t.Run("SRVUpstreams dial closure empty netAddrs", func(t *testing.T) {
		su := &SRVUpstreams{
			Resolver: &UpstreamResolver{},
		}
		su.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if len(su.Resolver.netAddrs) == 0 {
					return nil, fmt.Errorf("no resolver addresses available")
				}
				addr := su.Resolver.netAddrs[0]
				return nil, fmt.Errorf("dialing %s", addr.String())
			},
		}
		_, err := su.resolver.Dial(ctx, "udp", "1.2.3.4:53")
		if err == nil {
			t.Errorf("expected error when netAddrs is empty, got nil")
		}
	})

	t.Run("AUpstreams dial closure empty netAddrs", func(t *testing.T) {
		au := &AUpstreams{
			Resolver: &UpstreamResolver{},
		}
		au.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if len(au.Resolver.netAddrs) == 0 {
					return nil, fmt.Errorf("no resolver addresses available")
				}
				addr := au.Resolver.netAddrs[0]
				return nil, fmt.Errorf("dialing %s", addr.String())
			},
		}
		_, err := au.resolver.Dial(ctx, "udp", "1.2.3.4:53")
		if err == nil {
			t.Errorf("expected error when netAddrs is empty, got nil")
		}
	})

	t.Run("HTTPTransport dial closure empty netAddrs", func(t *testing.T) {
		h := &HTTPTransport{
			Resolver: &UpstreamResolver{},
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if len(h.Resolver.netAddrs) == 0 {
					return nil, fmt.Errorf("no resolver addresses available")
				}
				addr := h.Resolver.netAddrs[0]
				return nil, fmt.Errorf("dialing %s", addr.String())
			},
		}
		_, err := resolver.Dial(ctx, "udp", "1.2.3.4:53")
		if err == nil {
			t.Errorf("expected error when netAddrs is empty, got nil")
		}
	})
}
