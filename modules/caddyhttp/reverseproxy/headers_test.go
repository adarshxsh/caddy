package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCanonicalizeForwardedHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    http.Header
		expected http.Header
	}{
		{
			name: "Non-canonical keys merged and removed",
			input: http.Header{
				"x-forwarded-for":   []string{"1.1.1.1"},
				"x-forwarded-proto": []string{"https"},
				"x-forwarded-host":  []string{"example.com"},
				"User-Agent":        []string{"curl/7.68.0"},
			},
			expected: http.Header{
				"X-Forwarded-For":   []string{"1.1.1.1"},
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"example.com"},
				"User-Agent":        []string{"curl/7.68.0"},
			},
		},
		{
			name: "Canonical and non-canonical merged in order",
			input: http.Header{
				"X-Forwarded-For": []string{"1.1.1.1"},
				"x-forwarded-for": []string{"2.2.2.2"},
			},
			expected: http.Header{
				"X-Forwarded-For": []string{"1.1.1.1", "2.2.2.2"},
			},
		},
		{
			name: "Preserve omit signal (nil slice)",
			input: http.Header{
				"X-Forwarded-For": nil,
				"x-forwarded-for": []string{"1.1.1.1"},
			},
			expected: http.Header{
				"X-Forwarded-For": nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canonicalizeForwardedHeaders(tc.input)
			if !reflect.DeepEqual(tc.input, tc.expected) {
				t.Errorf("got %#v, want %#v", tc.input, tc.expected)
			}
		})
	}
}

func TestAddForwardedHeaders_NonCanonicalUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header["x-forwarded-for"] = []string{"1.1.1.1"}
	req.Header["x-forwarded-proto"] = []string{"https"}
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

	if got := req.Header.Get("X-Forwarded-For"); got != "192.168.1.100" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "192.168.1.100")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}

	for _, nonCanonicalKey := range []string{"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"} {
		if _, exists := req.Header[nonCanonicalKey]; exists {
			t.Errorf("non-canonical key %q should be removed from header map", nonCanonicalKey)
		}
	}
}

func TestAddForwardedHeaders_NonCanonicalTrustedMerged(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header["X-Forwarded-For"] = []string{"1.1.1.1"}
	req.Header["x-forwarded-for"] = []string{"2.2.2.2"}
	req.Header["x-forwarded-proto"] = []string{"https"}
	req.Header["x-forwarded-host"] = []string{"original.com"}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
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

	for _, nonCanonicalKey := range []string{"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"} {
		if _, exists := req.Header[nonCanonicalKey]; exists {
			t.Errorf("non-canonical key %q should be removed from header map", nonCanonicalKey)
		}
	}
}

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
