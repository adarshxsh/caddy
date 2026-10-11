package reverseproxy

import (
	"context"
	"net/http"
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

func TestCopyResponseHeadersHandler_Include(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Include: []string{"x-custom-header", "X-Canonical-Header"},
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	hrc := &handleResponseContext{
		response: &http.Response{
			Header: http.Header{
				"x-custom-header":    []string{"custom-val"},
				"x-canonical-header": []string{"canonical-val"},
				"x-excluded-header":  []string{"excluded-val"},
			},
		},
	}
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()
	if got := resHeader.Get("x-custom-header"); got != "custom-val" {
		t.Errorf("expected x-custom-header 'custom-val', got %q", got)
	}
	if got := resHeader.Get("x-canonical-header"); got != "canonical-val" {
		t.Errorf("expected x-canonical-header 'canonical-val', got %q", got)
	}
	if got := resHeader.Get("x-excluded-header"); got != "" {
		t.Errorf("expected x-excluded-header to be absent, got %q", got)
	}
}

func TestCopyResponseHeadersHandler_Exclude(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Exclude: []string{"x-custom-header"},
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	hrc := &handleResponseContext{
		response: &http.Response{
			Header: http.Header{
				"x-custom-header": []string{"custom-val"},
				"x-kept-header":   []string{"kept-val"},
			},
		},
	}
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()
	if got := resHeader.Get("x-custom-header"); got != "" {
		t.Errorf("expected x-custom-header to be excluded, got %q", got)
	}
	if got := resHeader.Get("x-kept-header"); got != "kept-val" {
		t.Errorf("expected x-kept-header 'kept-val', got %q", got)
	}
}

