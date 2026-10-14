package reverseproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHTTPTransportUnmarshalCaddyFileWithCaPools(t *testing.T) {
	const test_der_1 = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name              string
		args              args
		expectedTLSConfig TLSConfig
		wantErr           bool
	}{
		{
			name: "tls_trust_pool without a module argument returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`http {
					tls_trust_pool
				}`),
			},
			wantErr: true,
		},
		{
			name: "providing both 'tls_trust_pool' and 'tls_trusted_ca_certs' returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline %s
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'tls_trust_pool' and 'tls_trusted_ca_certs' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline {
						trust_der	%s
					}
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "using 'inline' tls_trust_pool loads the module successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trust_pool inline {
							trust_der	%s
						}
					}
				`, test_der_1)),
			},
			expectedTLSConfig: TLSConfig{CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1))},
		},
		{
			name: "setting 'tls_trusted_ca_certs' and 'tls_trust_pool' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trusted_ca_certs %s
						tls_trust_pool inline {
							trust_der	%s
						}
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{}
			if err := ht.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expectedTLSConfig, ht.TLS) {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() = %v, want %v", ht, tt.expectedTLSConfig)
			}
		})
	}
}

func TestHTTPTransport_RequestHeaderOps_TLS(t *testing.T) {
	var ht HTTPTransport
	// When TLS is nil, expect no header ops
	if ops := ht.RequestHeaderOps(); ops != nil {
		t.Fatalf("expected nil HeaderOps when TLS is nil, got: %#v", ops)
	}

	// When TLS is configured, expect a HeaderOps that sets Host
	ht.TLS = &TLSConfig{}
	ops := ht.RequestHeaderOps()
	if ops == nil {
		t.Fatal("expected non-nil HeaderOps when TLS is set")
	}
	if ops.Set == nil {
		t.Fatalf("expected ops.Set to be non-nil, got nil")
	}
	if got := ops.Set.Get("Host"); got != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("unexpected Host value; want placeholder, got: %s", got)
	}
}

// TestHTTPTransport_DialTLSContext_ProxyProtocol verifies that when TLS and
// ProxyProtocol are both enabled, DialTLSContext is set. This is critical because
// ProxyProtocol modifies req.URL.Host to include client info with "->" separator
// (e.g., "[2001:db8::1]:12345->127.0.0.1:443"), which breaks Go's address parsing.
// Without a custom DialTLSContext, Go's HTTP library would fail with
// "too many colons in address" when trying to parse the mangled host.
func TestHTTPTransport_DialTLSContext_ProxyProtocol(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tests := []struct {
		name                     string
		tls                      *TLSConfig
		proxyProtocol            string
		serverNameHasPlaceholder bool
		expectDialTLSContext     bool
	}{
		{
			name:                 "no TLS, no proxy protocol",
			tls:                  nil,
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS without proxy protocol",
			tls:                  &TLSConfig{},
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS with proxy protocol v1",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v1",
			expectDialTLSContext: true,
		},
		{
			name:                 "TLS with proxy protocol v2",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v2",
			expectDialTLSContext: true,
		},
		{
			name:                     "TLS with placeholder ServerName",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
		{
			name:                     "TLS with placeholder ServerName and proxy protocol",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "v2",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{
				TLS:           tt.tls,
				ProxyProtocol: tt.proxyProtocol,
			}

			rt, err := ht.NewTransport(ctx)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}

			hasDialTLSContext := rt.DialTLSContext != nil
			if hasDialTLSContext != tt.expectDialTLSContext {
				t.Errorf("DialTLSContext set = %v, want %v", hasDialTLSContext, tt.expectDialTLSContext)
			}
		})
	}
}

// TestHTTPTransport_DialContext_DialInfoOverride is a regression test for
// issue #6447: a `tcp4/`-prefixed upstream silently fell back to plain `tcp`
// because dialContext only honored DialInfo for unix networks. PR #7300 widened
// the condition so DialInfo is honored when no upstream HTTP proxy is in use,
// and skipped (for non-unix networks) when one is. Both halves are pinned here.
func TestHTTPTransport_DialContext_DialInfoOverride(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ht := &HTTPTransport{}
	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	proxyURL, err := url.Parse("http://proxy.example:8080")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	tests := []struct {
		name        string
		proxy       bool
		dialInfo    string
		defaultAddr string
	}{
		{
			// no proxy: DialInfo should be applied, so the dial lands on
			// the live listener despite the bogus default address.
			name:        "honors DialInfo when no proxy",
			proxy:       false,
			dialInfo:    ln.Addr().String(),
			defaultAddr: "127.0.0.1:1",
		},
		{
			// proxy active: DialInfo must NOT be applied for non-unix
			// networks; the default address (the live listener) is used.
			name:        "skips DialInfo when proxy active",
			proxy:       true,
			dialInfo:    "127.0.0.1:1",
			defaultAddr: ln.Addr().String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialCtx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, make(map[string]any))
			caddyhttp.SetVar(dialCtx, dialInfoVarKey, DialInfo{
				Network: "tcp4",
				Address: tt.dialInfo,
			})
			if tt.proxy {
				caddyhttp.SetVar(dialCtx, proxyVarKey, proxyURL)
			}

			conn, err := rt.DialContext(dialCtx, "tcp", tt.defaultAddr)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			t.Cleanup(func() { conn.Close() })
			if got := conn.RemoteAddr().String(); got != ln.Addr().String() {
				t.Fatalf("conn.RemoteAddr() = %s, want %s", got, ln.Addr().String())
			}
		})
	}
}

func TestHTTPTransport_KeepAlivePool_IdleTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(100 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("Provision error: %v", err)
	}
	defer ht.Cleanup()

	// Perform first request
	req1, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest 1: %v", err)
	}
	res1, err := ht.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip 1 error: %v", err)
	}
	body1, err := io.ReadAll(res1.Body)
	res1.Body.Close()
	if err != nil || string(body1) != "ok" {
		t.Fatalf("RoundTrip 1 read error: %v, body: %s", err, body1)
	}

	// Sleep longer than ReadTimeout (250ms > 100ms)
	time.Sleep(250 * time.Millisecond)

	// Trace connection reuse on second request
	var reused bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reused = info.Reused
		},
	}

	req2, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest 2: %v", err)
	}
	req2 = req2.WithContext(httptrace.WithClientTrace(req2.Context(), trace))

	res2, err := ht.RoundTrip(req2)
	if err != nil {
		t.Fatalf("RoundTrip 2 error after idle interval: %v", err)
	}
	body2, err := io.ReadAll(res2.Body)
	res2.Body.Close()
	if err != nil || string(body2) != "ok" {
		t.Fatalf("RoundTrip 2 read error: %v, body: %s", err, body2)
	}

	if !reused {
		t.Fatalf("expected keep-alive connection to be reused across idle interval exceeding ReadTimeout, but connection was not reused")
	}
}

func TestHTTPTransport_ActiveResponseBody_ReadTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Write first chunk
		_, _ = w.Write([]byte("chunk1"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Pause longer than ReadTimeout (250ms > 100ms) before second chunk
		time.Sleep(250 * time.Millisecond)
		_, _ = w.Write([]byte("chunk2"))
	}))
	defer ts.Close()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(100 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("Provision error: %v", err)
	}
	defer ht.Cleanup()

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := ht.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	defer res.Body.Close()

	buf := make([]byte, 10)
	n, err := res.Body.Read(buf)
	if err != nil {
		t.Fatalf("First chunk Read error: %v", err)
	}
	if string(buf[:n]) != "chunk1" {
		t.Fatalf("Expected 'chunk1', got: %s", string(buf[:n]))
	}

	// Second read should time out while server is sleeping
	_, err = res.Body.Read(buf)
	if err == nil {
		t.Fatalf("Expected timeout error on second chunk Read, got nil")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Expected net.Error timeout, got: %v", err)
	}
}

type slowBody struct {
	readCalled bool
}

func (s *slowBody) Read(p []byte) (int, error) {
	if !s.readCalled {
		s.readCalled = true
		copy(p, []byte("data"))
		return 4, nil
	}
	// Pause longer than WriteTimeout (250ms > 100ms)
	time.Sleep(250 * time.Millisecond)
	return 0, io.EOF
}

func (s *slowBody) Close() error {
	return nil
}

func TestHTTPTransport_ActiveRequestBody_WriteTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ht := &HTTPTransport{
		WriteTimeout: caddy.Duration(100 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("Provision error: %v", err)
	}
	defer ht.Cleanup()

	req, err := http.NewRequest("POST", ts.URL, &slowBody{})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	res, err := ht.RoundTrip(req)
	if err == nil {
		_, _ = io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("Expected error during request body write due to WriteTimeout, got nil")
	}
}
