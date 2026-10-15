package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	h := http.Header{
		"x-forwarded-for": []string{"1.2.3.4"},
		"X-Forwarded-For": []string{"5.6.7.8"},
		"X-FORWARDED-FOR": []string{"9.0.0.1"},
		"User-Agent":      []string{"test"},
	}

	deleteHeaderCaseInsensitive(h, "X-Forwarded-For")

	for k := range h {
		if strings.EqualFold(k, "X-Forwarded-For") {
			t.Errorf("expected key %q to be deleted, but it remained", k)
		}
	}
	if got := h.Get("User-Agent"); got != "test" {
		t.Errorf("User-Agent = %q, want %q", got, "test")
	}
}

func TestAllHeaderValues_CaseInsensitive(t *testing.T) {
	h := http.Header{
		"x-forwarded-for": []string{"1.2.3.4"},
		"X-Forwarded-For": []string{"5.6.7.8", "9.0.0.1"},
	}

	val, ok, omit := allHeaderValues(h, "X-Forwarded-For")
	if !ok || omit {
		t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
	}
	want := "5.6.7.8, 9.0.0.1, 1.2.3.4"
	if val != want {
		t.Errorf("allHeaderValues = %q, want %q", val, want)
	}

	// Test omit behavior
	hOmit := http.Header{
		"x-forwarded-for": nil,
	}
	_, ok, omit = allHeaderValues(hOmit, "X-Forwarded-For")
	if !ok || !omit {
		t.Errorf("expected ok=true, omit=true for nil header; got ok=%v, omit=%v", ok, omit)
	}
}

func TestLastHeaderValue_CaseInsensitive(t *testing.T) {
	h := http.Header{
		"X-Forwarded-Proto": []string{"http"},
		"x-forwarded-proto": []string{"https"},
	}

	val, ok, omit := lastHeaderValue(h, "X-Forwarded-Proto")
	if !ok || omit {
		t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
	}
	want := "https"
	if val != want {
		t.Errorf("lastHeaderValue = %q, want %q", val, want)
	}

	// Test omit behavior
	hOmit := http.Header{
		"x-forwarded-proto": nil,
	}
	_, ok, omit = lastHeaderValue(hOmit, "X-Forwarded-Proto")
	if !ok || !omit {
		t.Errorf("expected ok=true, omit=true for nil header; got ok=%v, omit=%v", ok, omit)
	}
}

func TestAddForwardedHeaders_NonCanonicalUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header["x-forwarded-for"] = []string{"1.2.3.4"}
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

	// Verify non-canonical keys are removed
	for k := range req.Header {
		if k == "x-forwarded-for" || k == "X-FORWARDED-PROTO" || k == "x-forwarded-host" {
			t.Errorf("non-canonical header key %q should be deleted", k)
		}
	}

	// Verify canonical values set correctly for untrusted client
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "203.0.113.10")
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
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header["x-forwarded-for"] = []string{"1.2.3.4"}
	req.Header["X-FORWARDED-PROTO"] = []string{"https"}
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

	// Verify non-canonical keys are removed
	for k := range req.Header {
		if k == "x-forwarded-for" || k == "X-FORWARDED-PROTO" || k == "x-forwarded-host" {
			t.Errorf("non-canonical header key %q should be deleted", k)
		}
	}

	// Verify canonical values are extracted from non-canonical keys and forwarded
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
