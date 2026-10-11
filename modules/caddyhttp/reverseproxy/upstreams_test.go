package reverseproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/caddyserver/caddy/v2"
)

type mockDNSServer struct {
	pc     net.PacketConn
	server *dns.Server
	mu     sync.Mutex
	srvs   map[string][]*dns.SRV
	fail   bool
}

func startMockDNSServer(t *testing.T) *mockDNSServer {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	m := &mockDNSServer{
		pc:   pc,
		srvs: make(map[string][]*dns.SRV),
	}
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m.mu.Lock()
			defer m.mu.Unlock()

			msg := new(dns.Msg)
			msg.SetReply(r)

			if m.fail {
				msg.Rcode = dns.RcodeServerFailure
				w.WriteMsg(msg)
				return
			}

			if len(r.Question) > 0 {
				q := r.Question[0]
				if records, ok := m.srvs[q.Name]; ok {
					for _, rec := range records {
						msg.Answer = append(msg.Answer, rec)
					}
				}
			}
			w.WriteMsg(msg)
		}),
	}
	m.server = server
	go server.ActivateAndServe()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	return m
}

func TestSRVUpstreamsGetUpstreams(t *testing.T) {
	mockDNS := startMockDNSServer(t)
	mockDNS.srvs["_http._tcp.example.com."] = []*dns.SRV{
		{
			Hdr:      dns.RR_Header{Name: "_http._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
			Target:   "target.example.com.",
			Port:     8080,
			Priority: 10,
			Weight:   10,
		},
	}

	su := SRVUpstreams{
		Service:     "http",
		Proto:       "tcp",
		Name:        "example.com",
		Refresh:     caddy.Duration(100 * time.Millisecond),
		GracePeriod: caddy.Duration(50 * time.Millisecond), // GracePeriod < Refresh
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("udp", mockDNS.pc.LocalAddr().String())
			},
		},
	}

	newReq := func() *http.Request {
		req := httptest.NewRequest("GET", "http://localhost", nil)
		repl := caddy.NewReplacer()
		return req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	}

	// 1. Initial lookup with empty cache and DNS failure -> returns error immediately
	t.Run("empty cache failure returns error immediately", func(t *testing.T) {
		_ = su.ResetCache(nil)
		mockDNS.mu.Lock()
		mockDNS.fail = true
		mockDNS.mu.Unlock()

		upstreams, err := su.GetUpstreams(newReq())
		if err == nil {
			t.Fatalf("expected error on empty cache failure, got nil error with upstreams: %v", upstreams)
		}
		if len(upstreams) != 0 {
			t.Fatalf("expected 0 upstreams on error, got %d", len(upstreams))
		}
	})

	// 2. Successful resolution caches upstreams
	t.Run("successful lookup caches upstreams", func(t *testing.T) {
		_ = su.ResetCache(nil)
		mockDNS.mu.Lock()
		mockDNS.fail = false
		mockDNS.mu.Unlock()

		req := newReq()
		upstreams, err := su.GetUpstreams(req)
		if err != nil {
			t.Fatalf("unexpected error on successful lookup: %v", err)
		}
		if len(upstreams) != 1 {
			t.Fatalf("expected 1 upstream, got %d", len(upstreams))
		}
		if upstreams[0].Dial != "target.example.com.:8080" {
			t.Fatalf("expected target.example.com.:8080, got %s", upstreams[0].Dial)
		}
	})

	// 3. Grace period fallback when GracePeriod < Refresh and cache is non-empty
	t.Run("grace period fallback when GracePeriod < Refresh", func(t *testing.T) {
		_ = su.ResetCache(nil)
		mockDNS.mu.Lock()
		mockDNS.fail = false
		mockDNS.mu.Unlock()

		req := newReq()
		// First lookup succeeds
		upstreams, err := su.GetUpstreams(req)
		if err != nil || len(upstreams) != 1 {
			t.Fatalf("initial lookup failed: %v", err)
		}

		// Enable DNS failure
		mockDNS.mu.Lock()
		mockDNS.fail = true
		mockDNS.mu.Unlock()

		// Wait for Refresh interval (100ms) to expire
		time.Sleep(120 * time.Millisecond)

		// GetUpstreams should invoke DNS, fail, but return cached upstreams because GracePeriod > 0 and cache is non-empty
		upstreams, err = su.GetUpstreams(req)
		if err != nil {
			t.Fatalf("expected cached upstreams during grace period fallback, got error: %v", err)
		}
		if len(upstreams) != 1 {
			t.Fatalf("expected 1 cached upstream during grace period, got %d", len(upstreams))
		}

		// Second request within GracePeriod (50ms) should be served directly from fresh cache without making a new DNS query
		upstreams, err = su.GetUpstreams(req)
		if err != nil {
			t.Fatalf("expected cached upstreams during grace period window, got error: %v", err)
		}
		if len(upstreams) != 1 {
			t.Fatalf("expected 1 cached upstream during grace period window, got %d", len(upstreams))
		}
	})

	// 4. Failure without grace period returns error
	t.Run("DNS failure without grace period returns error", func(t *testing.T) {
		suNoGrace := su
		suNoGrace.GracePeriod = 0

		_ = suNoGrace.ResetCache(nil)
		mockDNS.mu.Lock()
		mockDNS.fail = false
		mockDNS.mu.Unlock()

		req := newReq()
		// Initial lookup succeeds
		upstreams, err := suNoGrace.GetUpstreams(req)
		if err != nil || len(upstreams) != 1 {
			t.Fatalf("initial lookup failed: %v", err)
		}

		// Enable DNS failure
		mockDNS.mu.Lock()
		mockDNS.fail = true
		mockDNS.mu.Unlock()

		// Wait for Refresh interval (100ms) to expire
		time.Sleep(120 * time.Millisecond)

		// GetUpstreams should attempt DNS, fail, and return error since GracePeriod == 0
		upstreams, err = suNoGrace.GetUpstreams(req)
		if err == nil {
			t.Fatalf("expected error when GracePeriod == 0 and DNS fails, got nil with upstreams: %v", upstreams)
		}
	})
}

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
