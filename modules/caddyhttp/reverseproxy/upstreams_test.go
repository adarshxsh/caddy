package reverseproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on packet: %v", err)
	}

	var failDNS atomic.Bool

	server := &dns.Server{PacketConn: pc, Net: "udp"}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if failDNS.Load() {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}

		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeSRV {
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 10,
				Weight:   20,
				Port:     8080,
				Target:   "backend.local.",
			})
		}
		_ = w.WriteMsg(m)
	})

	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	makeRequest := func() *http.Request {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		repl := caddy.NewReplacer()
		return req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	}

	// 1. Initial lookup fails with GracePeriod > 0 and no cached upstreams.
	// Must return an error and not empty upstreams.
	failDNS.Store(true)
	suNoCache := SRVUpstreams{
		Name:        "example.com",
		Refresh:     caddy.Duration(500 * time.Millisecond),
		GracePeriod: caddy.Duration(200 * time.Millisecond),
		logger:      zap.NewNop(),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", pc.LocalAddr().String())
			},
		},
	}
	_ = suNoCache.ResetCache(nil)

	req := makeRequest()
	up, err := suNoCache.GetUpstreams(req)
	if err == nil {
		t.Fatalf("expected error on initial DNS lookup failure, got upstreams: %v", up)
	}

	// 2. Initial lookup succeeds, then DNS fails when GracePeriod < Refresh.
	failDNS.Store(false)
	su := SRVUpstreams{
		Name:        "example.com",
		Refresh:     caddy.Duration(250 * time.Millisecond),
		GracePeriod: caddy.Duration(100 * time.Millisecond),
		logger:      zap.NewNop(),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if failDNS.Load() {
					return nil, errors.New("dns lookup dial error")
				}
				return net.Dial("udp", pc.LocalAddr().String())
			},
		},
	}
	_ = su.ResetCache(nil)

	req = makeRequest()
	up, err = su.GetUpstreams(req)
	if err != nil {
		t.Fatalf("unexpected error on initial successful DNS lookup: %v", err)
	}
	if len(up) != 1 || up[0].Dial != "backend.local.:8080" {
		t.Fatalf("unexpected upstreams returned: %v", up)
	}

	// Simulate DNS outage
	failDNS.Store(true)

	// Wait for Refresh interval (250ms) to pass so cached value expires
	time.Sleep(300 * time.Millisecond)

	// Now GetUpstreams should fail DNS lookup but fall back to grace period caching
	req = makeRequest()
	up, err = su.GetUpstreams(req)
	if err != nil {
		t.Fatalf("expected grace period fallback to return cached upstreams, got error: %v", err)
	}
	if len(up) != 1 || up[0].Dial != "backend.local.:8080" {
		t.Fatalf("unexpected upstreams returned during grace period: %v", up)
	}

	// Immediate subsequent lookup during GracePeriod should still return cached upstreams
	req = makeRequest()
	up, err = su.GetUpstreams(req)
	if err != nil {
		t.Fatalf("expected cached upstreams during grace period, got error: %v", err)
	}
	if len(up) != 1 || up[0].Dial != "backend.local.:8080" {
		t.Fatalf("unexpected upstreams returned during grace period: %v", up)
	}

	// Wait for GracePeriod (100ms) to pass
	time.Sleep(150 * time.Millisecond)

	// DNS is still down, and GracePeriod expired. GetUpstreams should now attempt lookup and fail if GracePeriod is 0.
	suZeroGrace := su
	suZeroGrace.GracePeriod = 0

	req = makeRequest()
	up, err = suZeroGrace.GetUpstreams(req)
	if err == nil {
		t.Fatalf("expected error when GracePeriod is 0 and DNS fails, got upstreams: %v", up)
	}
}
