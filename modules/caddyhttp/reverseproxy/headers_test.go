package reverseproxy

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestAddForwardedHeadersNonIP(t *testing.T) {
	h := Handler{}

	// Simulate a request with a non-IP remote address (e.g. SCION, abstract socket, or hostname)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "my-weird-network:12345"

	// Mock the context variables required by Caddy.
	// We need to inject the variable map manually since we aren't running the full server.
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	// Execute the unexported function
	err := h.addForwardedHeaders(req)

	// Expectation: No error should be returned for non-IP addresses.
	// The function should simply skip the trusted proxy check.
	if err != nil {
		t.Errorf("expected no error for non-IP address, got: %v", err)
	}
}

func TestAddForwardedHeaders_UnixSocketTrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "original.example.com")

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
		caddyhttp.ClientIPVarKey:     "1.2.3.4",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4, 10.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4, 10.0.0.1")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "original.example.com")
	}
}

func TestAddForwardedHeaders_UnixSocketUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spoofed.example.com")

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For should be deleted, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "" {
		t.Errorf("X-Forwarded-Proto should be deleted, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Errorf("X-Forwarded-Host should be deleted, got %q", got)
	}
}

func TestAddForwardedHeaders_UnixSocketTrustedNoExistingHeaders(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
		caddyhttp.ClientIPVarKey:     "5.6.7.8",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For should be empty when no prior XFF exists, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

func TestEarlyDataHeaderSanitization(t *testing.T) {
	h := Handler{}

	tests := []struct {
		name          string
		tlsState      *tls.ConnectionState
		inputHeaders  map[string]string
		wantEarlyData string
		wantExists    bool
	}{
		{
			name:         "HTTP request with spoofed Early-Data header",
			tlsState:     nil,
			inputHeaders: map[string]string{"Early-Data": "1"},
			wantExists:   false,
		},
		{
			name:         "Completed TLS request with spoofed Early-Data header",
			tlsState:     &tls.ConnectionState{HandshakeComplete: true},
			inputHeaders: map[string]string{"Early-Data": "1"},
			wantExists:   false,
		},
		{
			name:          "TLS early data request (HandshakeComplete false) without prior Early-Data header",
			tlsState:      &tls.ConnectionState{HandshakeComplete: false},
			inputHeaders:  map[string]string{},
			wantEarlyData: "1",
			wantExists:    true,
		},
		{
			name:          "TLS early data request (HandshakeComplete false) with prior Early-Data header",
			tlsState:      &tls.ConnectionState{HandshakeComplete: false},
			inputHeaders:  map[string]string{"Early-Data": "1"},
			wantEarlyData: "1",
			wantExists:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.TLS = tt.tlsState
			for k, v := range tt.inputHeaders {
				req.Header.Set(k, v)
			}

			vars := map[string]any{
				caddyhttp.TrustedProxyVarKey: false,
				caddyhttp.ClientIPVarKey:     "127.0.0.1",
			}
			ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
			req = req.WithContext(ctx)

			outReq, err := h.prepareRequest(req, caddy.NewReplacer())
			if err != nil {
				t.Fatalf("prepareRequest unexpected error: %v", err)
			}

			gotVal := outReq.Header.Get("Early-Data")
			_, gotExists := outReq.Header["Early-Data"]

			if tt.wantExists {
				if !gotExists {
					t.Errorf("expected Early-Data header to exist, but it was missing")
				}
				if gotVal != tt.wantEarlyData {
					t.Errorf("Early-Data header = %q, want %q", gotVal, tt.wantEarlyData)
				}
			} else {
				if gotExists {
					t.Errorf("expected Early-Data header to be deleted, but found = %q", gotVal)
				}
			}
		})
	}
}
