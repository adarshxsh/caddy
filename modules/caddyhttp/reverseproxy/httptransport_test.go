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
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestHTTPTransport_ConditionalReadDeadline_IdleConnKeepAlive(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	readTimeout := 150 * time.Millisecond
	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(readTimeout),
		KeepAlive: &KeepAlive{
			IdleConnTimeout: caddy.Duration(2 * time.Second),
		},
	}

	err := ht.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision error: %v", err)
	}

	reqURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse URL error: %v", err)
	}

	// First request
	req1 := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	resp1, err := ht.RoundTrip(req1)
	if err != nil {
		t.Fatalf("First RoundTrip error: %v", err)
	}
	body1, err := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if err != nil || string(body1) != "ok" {
		t.Fatalf("First request body error: %v, got %s", err, string(body1))
	}

	// Sleep longer than ReadTimeout (300ms > 150ms) while connection is idle in pool
	time.Sleep(300 * time.Millisecond)

	// Second request on the same idle connection
	req2 := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	resp2, err := ht.RoundTrip(req2)
	if err != nil {
		t.Fatalf("Second RoundTrip error after idle interval: %v", err)
	}
	body2, err := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if err != nil || string(body2) != "ok" {
		t.Fatalf("Second request body error: %v, got %s", err, string(body2))
	}
}

func TestHTTPTransport_ConditionalReadDeadline_ActiveReadTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Delay longer than ReadTimeout before writing remaining bytes
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("1234567890"))
	}))
	defer server.Close()

	readTimeout := 100 * time.Millisecond
	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(readTimeout),
	}

	err := ht.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision error: %v", err)
	}

	reqURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse URL error: %v", err)
	}

	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}

	resp, err := ht.RoundTrip(req)
	if err != nil {
		// Response header read timed out
		return
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("Expected active read timeout error, got nil")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// PASS
	} else if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "deadline exceeded") {
		// PASS
	} else {
		t.Fatalf("Expected timeout error, got: %v", err)
	}
}

func TestHTTPTransport_ConditionalReadDeadline_HTTP2Multiplexed(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("h2-ok"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	readTimeout := 150 * time.Millisecond
	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(readTimeout),
		Versions:    []string{"2"},
		TLS: &TLSConfig{
			InsecureSkipVerify: true,
		},
	}

	err := ht.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision error: %v", err)
	}

	reqURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse URL error: %v", err)
	}

	// Request 1
	req1 := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	resp1, err := ht.RoundTrip(req1)
	if err != nil {
		t.Fatalf("H2 First RoundTrip error: %v", err)
	}
	body1, err := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if err != nil || string(body1) != "h2-ok" {
		t.Fatalf("H2 First request body error: %v, got %s", err, string(body1))
	}

	// Idle gap longer than ReadTimeout
	time.Sleep(300 * time.Millisecond)

	// Request 2 on same multiplexed H2 connection
	req2 := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	resp2, err := ht.RoundTrip(req2)
	if err != nil {
		t.Fatalf("H2 Second RoundTrip error after idle window: %v", err)
	}
	body2, err := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if err != nil || string(body2) != "h2-ok" {
		t.Fatalf("H2 Second request body error: %v, got %s", err, string(body2))
	}
}

func TestHTTPTransport_SetReadDeadline_ErrorLogging(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	logger := zap.New(core)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}

	tcpConn := conn.(*net.TCPConn)
	// Close connection so SetReadDeadline fails
	tcpConn.Close()

	wrapper := &tcpRWTimeoutConn{
		TCPConn:     tcpConn,
		readTimeout: 100 * time.Millisecond,
		logger:      logger,
	}

	wrapper.clearReadDeadline()

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("Expected log entry on failed SetReadDeadline, got none")
	}
	if entries[0].Level != zapcore.ErrorLevel {
		t.Errorf("Expected ErrorLevel log, got %v", entries[0].Level)
	}
	if entries[0].Message != "failed to set read deadline" {
		t.Errorf("Expected message 'failed to set read deadline', got %q", entries[0].Message)
	}
}

