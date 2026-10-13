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

func TestDelHeaderCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header["x-forwarded-for"] = []string{"1.2.3.4"}
	req.Header["X-FORWARDED-FOR"] = []string{"5.6.7.8"}
	req.Header["X-Forwarded-Proto"] = []string{"https"}

	delHeaderCaseInsensitive(req.Header, "X-Forwarded-For")

	for k := range req.Header {
		if k == "x-forwarded-for" || k == "X-FORWARDED-FOR" || k == "X-Forwarded-For" {
			t.Errorf("header key %q should have been deleted", k)
		}
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto should remain intact, got %q", got)
	}
}

func TestHeaderLookupCaseInsensitive(t *testing.T) {
	t.Run("allHeaderValues with lowercase key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header["x-forwarded-for"] = []string{"1.1.1.1", "2.2.2.2"}

		val, ok, omit := allHeaderValues(req.Header, "X-Forwarded-For")
		if !ok || omit {
			t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
		}
		if val != "1.1.1.1, 2.2.2.2" {
			t.Errorf("allHeaderValues = %q, want %q", val, "1.1.1.1, 2.2.2.2")
		}
	})

	t.Run("lastHeaderValue with uppercase key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header["X-FORWARDED-PROTO"] = []string{"http", "https"}

		val, ok, omit := lastHeaderValue(req.Header, "X-Forwarded-Proto")
		if !ok || omit {
			t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
		}
		if val != "https" {
			t.Errorf("lastHeaderValue = %q, want %q", val, "https")
		}
	})

	t.Run("multiple non-canonical key variants", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header["X-Forwarded-For"] = []string{"10.0.0.1"}
		req.Header["x-forwarded-for"] = []string{"10.0.0.2"}

		val, ok, omit := allHeaderValues(req.Header, "X-Forwarded-For")
		if !ok || omit {
			t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
		}
		if val != "10.0.0.1, 10.0.0.2" {
			t.Errorf("allHeaderValues = %q, want %q", val, "10.0.0.1, 10.0.0.2")
		}

		lastVal, ok, omit := lastHeaderValue(req.Header, "X-Forwarded-For")
		if !ok || omit {
			t.Fatalf("expected ok=true, omit=false; got ok=%v, omit=%v", ok, omit)
		}
		if lastVal != "10.0.0.2" {
			t.Errorf("lastHeaderValue = %q, want %q", lastVal, "10.0.0.2")
		}
	})

	t.Run("header omission with nil slice", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header["x-forwarded-for"] = nil

		_, ok, omit := allHeaderValues(req.Header, "X-Forwarded-For")
		if !ok || !omit {
			t.Errorf("expected ok=true, omit=true for nil header slice; got ok=%v, omit=%v", ok, omit)
		}
	})
}

func TestAddForwardedHeadersCaseInsensitiveUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.195:12345"

	req.Header["x-forwarded-for"] = []string{"spoofed-ip-1"}
	req.Header["X-FORWARDED-FOR"] = []string{"spoofed-ip-2"}
	req.Header["x-forwarded-proto"] = []string{"https"}
	req.Header["X-FORWARDED-HOST"] = []string{"spoofed.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify all non-canonical key variations are deleted
	for k := range req.Header {
		if k == "x-forwarded-for" || k == "X-FORWARDED-FOR" || k == "x-forwarded-proto" || k == "X-FORWARDED-HOST" {
			t.Errorf("non-canonical header key %q was not removed", k)
		}
	}

	// Verify sanitized canonical values
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.195" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "203.0.113.195")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

func TestAddForwardedHeadersCaseInsensitiveTrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.1:12345"

	req.Header["x-forwarded-for"] = []string{"1.2.3.4"}
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

	for k := range req.Header {
		if k == "x-forwarded-for" || k == "x-forwarded-proto" || k == "x-forwarded-host" {
			t.Errorf("non-canonical header key %q was not removed", k)
		}
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4, 198.51.100.1" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4, 198.51.100.1")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "original.example.com")
	}
}
