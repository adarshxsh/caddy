package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDeleteHeader(t *testing.T) {
	h := http.Header{
		"Connection":        []string{"close"},
		"connection":        []string{"keep-alive"},
		"CONNECTION":        []string{"upgrade"},
		"Transfer-Encoding": []string{"chunked"},
		"keep-alive":        []string{"timeout=5"},
	}

	deleteHeader(h, "Connection")

	for k := range h {
		if strings.EqualFold(k, "Connection") {
			t.Errorf("expected header %q to be deleted, but found key %q", "Connection", k)
		}
	}
}

func TestGetHeaderValues(t *testing.T) {
	h := http.Header{
		"Connection": []string{"close"},
		"connection": []string{"keep-alive"},
		"CONNECTION": []string{"upgrade"},
		"Other":      []string{"val"},
	}

	vals := getHeaderValues(h, "Connection")
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d: %v", len(vals), vals)
	}

	expected := map[string]bool{"close": true, "keep-alive": true, "upgrade": true}
	for _, v := range vals {
		if !expected[v] {
			t.Errorf("unexpected value %q in getHeaderValues result", v)
		}
	}
}

func TestRemoveConnectionHeadersCaseInsensitive(t *testing.T) {
	h := http.Header{
		"connection": []string{"X-Foo, X-Bar"},
		"CONNECTION": []string{"X-Baz"},
		"x-foo":      []string{"1"},
		"X-BAR":      []string{"2"},
		"X-Baz":      []string{"3"},
		"keep-alive": []string{"timeout=5"},
	}

	removeConnectionHeaders(h)

	for k := range h {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "X-Foo") || strings.EqualFold(k, "X-Bar") || strings.EqualFold(k, "X-Baz") {
			t.Errorf("expected header key %q to be removed, but key %q remains", k, k)
		}
	}

	vals := getHeaderValues(h, "keep-alive")
	if len(vals) == 0 || vals[0] != "timeout=5" {
		t.Errorf("expected keep-alive header to remain intact, got %v", vals)
	}
}

func TestUpgradeTypeCaseInsensitive(t *testing.T) {
	h := http.Header{
		"connection": []string{"upgrade"},
		"upgrade":    []string{"websocket"},
	}

	if got := upgradeType(h); got != "websocket" {
		t.Errorf("upgradeType = %q, want %q", got, "websocket")
	}
}

func TestHopByHopHeaderPurgingCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header["transfer-encoding"] = []string{"chunked"}
	req.Header["KEEP-ALIVE"] = []string{"timeout=5"}
	req.Header["proxy-authorization"] = []string{"basic xxx"}
	req.Header["te"] = []string{"trailers"}

	// Simulate request preparation hop-by-hop purging logic
	reqUpgradeType := upgradeType(req.Header)
	removeConnectionHeaders(req.Header)

	for _, h := range hopHeaders {
		if h == "Te" && httpguts.HeaderValuesContainsToken(getHeaderValues(req.Header, "Te"), "trailers") {
			deleteHeader(req.Header, "Te")
			req.Header.Set("Te", "trailers")
			continue
		}
		deleteHeader(req.Header, h)
	}

	if reqUpgradeType != "" {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", reqUpgradeType)
	}

	if got := req.Header.Get("Te"); got != "trailers" {
		t.Errorf("expected Te header to be 'trailers', got %q", got)
	}

	for k := range req.Header {
		if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Keep-Alive") || strings.EqualFold(k, "Proxy-Authorization") {
			t.Errorf("expected hop-by-hop header %q to be purged, found key %q", k, k)
		}
	}

	// Test response preparation hop-by-hop purging logic
	resHeader := http.Header{
		"transfer-encoding": []string{"chunked"},
		"KEEP-ALIVE":        []string{"timeout=5"},
		"connection":        []string{"close"},
		"X-Custom-Header":   []string{"value"},
	}

	removeConnectionHeaders(resHeader)
	for _, h := range hopHeaders {
		deleteHeader(resHeader, h)
	}

	for k := range resHeader {
		if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Keep-Alive") || strings.EqualFold(k, "Connection") {
			t.Errorf("expected hop-by-hop response header %q to be purged, found key %q", k, k)
		}
	}

	if got := resHeader.Get("X-Custom-Header"); got != "value" {
		t.Errorf("expected X-Custom-Header to remain, got %q", got)
	}
}
