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

func TestAddForwardedHeaders_UntrustedNonCanonicalHeaders(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header["x-forwarded-for"] = []string{"9.9.9.9"}
	req.Header["X-FORWARDED-PROTO"] = []string{"https"}
	req.Header["x-forwarded-host"] = []string{"spoofed.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Non-canonical keys should be completely purged from req.Header map
	for _, badKey := range []string{"x-forwarded-for", "X-FORWARDED-PROTO", "x-forwarded-host"} {
		if _, exists := req.Header[badKey]; exists {
			t.Errorf("non-canonical key %q should have been deleted from req.Header", badKey)
		}
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

func TestAddForwardedHeaders_TrustedNonCanonicalHeaders(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header["X-Forwarded-For"] = []string{"1.1.1.1"}
	req.Header["x-forwarded-for"] = []string{"2.2.2.2"}
	req.Header["x-forwarded-proto"] = []string{"https"}
	req.Header["X-FORWARDED-HOST"] = []string{"original.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	for _, badKey := range []string{"x-forwarded-for", "x-forwarded-proto", "X-FORWARDED-HOST"} {
		if _, exists := req.Header[badKey]; exists {
			t.Errorf("non-canonical key %q should have been deleted from req.Header", badKey)
		}
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "1.1.1.1, 2.2.2.2, 10.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.1.1.1, 2.2.2.2, 10.0.0.1")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "original.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "original.com")
	}
}

func TestAddForwardedHeaders_OmitMarkerNonCanonical(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header["X-Forwarded-For"] = nil
	req.Header["x-forwarded-for"] = []string{"9.9.9.9"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if _, exists := req.Header["x-forwarded-for"]; exists {
		t.Errorf("x-forwarded-for should have been deleted due to omit marker")
	}
	if _, exists := req.Header["X-Forwarded-For"]; exists {
		t.Errorf("X-Forwarded-For should have been purged when omitted")
	}
}

func TestHeaderFoldHelpers(t *testing.T) {
	hdr := make(http.Header)
	hdr["x-forwarded-for"] = []string{"1.1.1.1"}
	hdr["X-FORWARDED-FOR"] = []string{"2.2.2.2"}

	// Keys sorted alphabetically: "X-FORWARDED-FOR" comes before "x-forwarded-for"
	val, ok, omit := allHeaderValues(hdr, "X-Forwarded-For")
	if !ok || omit || val != "2.2.2.2, 1.1.1.1" {
		t.Errorf("allHeaderValues = (%q, %v, %v), want (%q, true, false)", val, ok, omit, "2.2.2.2, 1.1.1.1")
	}

	val, ok, omit = lastHeaderValue(hdr, "X-Forwarded-For")
	if !ok || omit || val != "1.1.1.1" {
		t.Errorf("lastHeaderValue = (%q, %v, %v), want (%q, true, false)", val, ok, omit, "1.1.1.1")
	}

	setHeaderFold(hdr, "X-Forwarded-For", "3.3.3.3")
	if _, exists := hdr["x-forwarded-for"]; exists {
		t.Errorf("x-forwarded-for should be deleted after setHeaderFold")
	}
	if _, exists := hdr["X-FORWARDED-FOR"]; exists {
		t.Errorf("X-FORWARDED-FOR should be deleted after setHeaderFold")
	}
	if got := hdr.Get("X-Forwarded-For"); got != "3.3.3.3" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "3.3.3.3")
	}
}
