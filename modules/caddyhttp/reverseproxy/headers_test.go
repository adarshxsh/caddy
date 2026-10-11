package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http/httpguts"

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

func TestDelHeaderIgnoreCase(t *testing.T) {
	h := http.Header{
		"connection": []string{"close"},
		"Connection": []string{"keep-alive"},
		"Keep-Alive": []string{"timeout=5"},
		"X-Custom":   []string{"foo"},
	}

	delHeaderIgnoreCase(h, "CONNECTION")

	if len(getHeaderValuesIgnoreCase(h, "Connection")) != 0 {
		t.Errorf("expected Connection header to be fully deleted, got: %v", h)
	}
	if got := h.Get("X-Custom"); got != "foo" {
		t.Errorf("expected X-Custom to remain 'foo', got: %q", got)
	}
}

func TestGetHeaderValuesIgnoreCase(t *testing.T) {
	h := http.Header{
		"connection": []string{"close"},
		"Connection": []string{"upgrade"},
	}

	vals := getHeaderValuesIgnoreCase(h, "CONNECTION")
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d: %v", len(vals), vals)
	}
}

func TestRemoveConnectionHeaders_CaseInsensitive(t *testing.T) {
	h := http.Header{
		"connection":    []string{"custom-header, keep-alive"},
		"custom-header": []string{"value1"},
		"Keep-Alive":    []string{"timeout=5"},
		"X-Keep":        []string{"value2"},
	}

	removeConnectionHeaders(h)

	if len(getHeaderValuesIgnoreCase(h, "custom-header")) != 0 {
		t.Errorf("custom-header should have been deleted, still present: %v", h)
	}
	if len(getHeaderValuesIgnoreCase(h, "keep-alive")) != 0 {
		t.Errorf("Keep-Alive should have been deleted, still present: %v", h)
	}
	if got := h.Get("X-Keep"); got != "value2" {
		t.Errorf("X-Keep should remain, got %q", got)
	}
}

func TestUpgradeType_CaseInsensitive(t *testing.T) {
	h := http.Header{
		"connection": []string{"upgrade"},
		"upgrade":    []string{"websocket"},
	}

	got := upgradeType(h)
	if got != "websocket" {
		t.Errorf("expected upgradeType to be 'websocket', got %q", got)
	}
}

func TestCopyHeader_NoForwardNonCanonicalHeaders(t *testing.T) {
	reqHeader := http.Header{
		"connection": []string{"close"},
		"keep-alive": []string{"timeout=5"},
		"te":         []string{"trailers"},
		"x-custom":   []string{"ok"},
	}

	removeConnectionHeaders(reqHeader)
	for _, h := range hopHeaders {
		if h == "Te" && httpguts.HeaderValuesContainsToken(getHeaderValuesIgnoreCase(reqHeader, "Te"), "trailers") {
			delHeaderIgnoreCase(reqHeader, "Te")
			reqHeader.Set("Te", "trailers")
			continue
		}
		delHeaderIgnoreCase(reqHeader, h)
	}

	dst := make(http.Header)
	copyHeader(dst, reqHeader)

	if got := dst.Get("Connection"); got != "" {
		t.Errorf("Connection header forwarded: %q", got)
	}
	if got := dst.Get("Keep-Alive"); got != "" {
		t.Errorf("Keep-Alive header forwarded: %q", got)
	}
	if got := dst.Get("Te"); got != "trailers" {
		t.Errorf("Te header expected 'trailers', got %q", got)
	}
	if got := dst.Get("X-Custom"); got != "ok" {
		t.Errorf("X-Custom header expected 'ok', got %q", got)
	}
}
