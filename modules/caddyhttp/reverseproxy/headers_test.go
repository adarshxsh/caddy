package reverseproxy

import (
	"context"
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

func TestAddForwardedHeaders_NonCanonicalUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Set lower-case (non-canonical) headers directly in map
	req.Header["x-forwarded-for"] = []string{"10.0.0.1"}
	req.Header["x-forwarded-proto"] = []string{"https"}
	req.Header["x-forwarded-host"] = []string{"spoofed.example.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Non-canonical map keys should be deleted
	if _, exists := req.Header["x-forwarded-for"]; exists {
		t.Errorf("non-canonical x-forwarded-for header map key still exists")
	}
	if _, exists := req.Header["x-forwarded-proto"]; exists {
		t.Errorf("non-canonical x-forwarded-proto header map key still exists")
	}
	if _, exists := req.Header["x-forwarded-host"]; exists {
		t.Errorf("non-canonical x-forwarded-host header map key still exists")
	}

	// Canonical headers should be set properly for untrusted client
	if got := req.Header.Get("X-Forwarded-For"); got != "192.168.1.100" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "192.168.1.100")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

func TestAddForwardedHeaders_NonCanonicalTrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Set lower-case (non-canonical) headers directly in map
	req.Header["x-forwarded-for"] = []string{"10.0.0.1"}
	req.Header["x-forwarded-proto"] = []string{"https"}
	req.Header["x-forwarded-host"] = []string{"original.example.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Non-canonical map keys should be purged
	if _, exists := req.Header["x-forwarded-for"]; exists {
		t.Errorf("non-canonical x-forwarded-for header map key still exists")
	}
	if _, exists := req.Header["x-forwarded-proto"]; exists {
		t.Errorf("non-canonical x-forwarded-proto header map key still exists")
	}
	if _, exists := req.Header["x-forwarded-host"]; exists {
		t.Errorf("non-canonical x-forwarded-host header map key still exists")
	}

	// Canonical headers should be set using trusted prior values
	if got := req.Header.Get("X-Forwarded-For"); got != "10.0.0.1, 192.168.1.100" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "10.0.0.1, 192.168.1.100")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "original.example.com")
	}
}

func TestDelHeaderFold(t *testing.T) {
	hdr := map[string][]string{
		"X-Forwarded-For": {"1.1.1.1"},
		"x-forwarded-for": {"2.2.2.2"},
		"X-FORWARDED-FOR": {"3.3.3.3"},
		"Other-Header":    {"val"},
	}

	delHeaderFold(hdr, "x-forwarded-for")

	if len(hdr) != 1 {
		t.Errorf("expected 1 header remaining, got %d", len(hdr))
	}
	if _, exists := hdr["Other-Header"]; !exists {
		t.Errorf("Other-Header should not have been deleted")
	}
}

func TestCaseInsensitiveHeaderLookups(t *testing.T) {
	hdr := map[string][]string{
		"x-forwarded-for": {"1.1.1.1"},
		"X-Forwarded-For": {"2.2.2.2"},
	}

	val, ok, omit := allHeaderValues(hdr, "X-Forwarded-For")
	if !ok || omit || val != "2.2.2.2, 1.1.1.1" {
		t.Errorf("allHeaderValues = (%q, %v, %v), want (%q, true, false)", val, ok, omit, "2.2.2.2, 1.1.1.1")
	}

	val, ok, omit = lastHeaderValue(hdr, "x-forwarded-for")
	if !ok || omit || val != "1.1.1.1" {
		t.Errorf("lastHeaderValue = (%q, %v, %v), want (%q, true, false)", val, ok, omit, "1.1.1.1")
	}

	// Test omit (nil slice)
	omitHdr := map[string][]string{
		"x-forwarded-proto": nil,
	}
	_, ok, omit = allHeaderValues(omitHdr, "X-Forwarded-Proto")
	if !ok || !omit {
		t.Errorf("allHeaderValues for nil slice = ok:%v omit:%v, want ok:true omit:true", ok, omit)
	}
	_, ok, omit = lastHeaderValue(omitHdr, "X-Forwarded-Proto")
	if !ok || !omit {
		t.Errorf("lastHeaderValue for nil slice = ok:%v omit:%v, want ok:true omit:true", ok, omit)
	}
}
