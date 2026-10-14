package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestCanonicalizeHeaders(t *testing.T) {
	h := http.Header{
		"connection":          []string{"close"},
		"CONNECTION":          []string{"keep-alive"},
		"alt-svc":             []string{"h3=\":443\""},
		"proxy-authorization": []string{"Basic abc"},
		"X-Custom-Header":     []string{"value1"},
	}

	canonicalizeHeaders(h)

	// Check that non-canonical keys were removed
	for _, nonCanonicalKey := range []string{"connection", "CONNECTION", "alt-svc", "proxy-authorization"} {
		if _, exists := h[nonCanonicalKey]; exists {
			t.Errorf("non-canonical key %q still exists in header map", nonCanonicalKey)
		}
	}

	// Check that canonical keys contain expected values
	if got := h["Connection"]; len(got) != 2 || (got[0] != "close" && got[1] != "close") {
		t.Errorf("Connection values = %v, want merged [close, keep-alive]", got)
	}
	if got := h.Get("Alt-Svc"); got != "h3=\":443\"" {
		t.Errorf("Alt-Svc = %q, want %q", got, "h3=\":443\"")
	}
	if got := h.Get("Proxy-Authorization"); got != "Basic abc" {
		t.Errorf("Proxy-Authorization = %q, want %q", got, "Basic abc")
	}
	if got := h.Get("X-Custom-Header"); got != "value1" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "value1")
	}
}

func TestRemoveConnectionHeaders(t *testing.T) {
	h := http.Header{
		"Connection":  []string{"close, backend-hop"},
		"Backend-Hop": []string{"secret"},
	}
	removeConnectionHeaders(h)
	t.Logf("h after removeConnectionHeaders = %#v", h)
	if _, exists := h["Backend-Hop"]; exists {
		t.Errorf("Backend-Hop still exists: %#v", h)
	}
}

func TestNonCanonicalHopByHopRemoval(t *testing.T) {
	reqHeader := http.Header{
		"connection":          []string{"close, custom-hop"},
		"custom-hop":          []string{"custom-val"},
		"alt-svc":             []string{"h3=\":443\""},
		"proxy-authorization": []string{"Bearer xyz"},
		"keep-alive":          []string{"timeout=5"},
		"transfer-encoding":   []string{"chunked"},
		"x-forwarded-for":     []string{"1.2.3.4"},
	}

	canonicalizeHeaders(reqHeader)
	removeConnectionHeaders(reqHeader)

	for _, h := range hopHeaders {
		reqHeader.Del(h)
	}

	// Verify all hop-by-hop headers (canonical or non-canonical) are absent
	for _, k := range []string{"connection", "Connection", "custom-hop", "Custom-Hop", "alt-svc", "Alt-Svc", "proxy-authorization", "Proxy-Authorization", "keep-alive", "Keep-Alive", "transfer-encoding", "Transfer-Encoding"} {
		if _, exists := reqHeader[k]; exists {
			t.Errorf("hop-by-hop key %q still exists in reqHeader map: %v", k, reqHeader[k])
		}
	}

	// Verify standard non-hop-by-hop headers were canonicalized and kept
	if got := reqHeader.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4")
	}
}
