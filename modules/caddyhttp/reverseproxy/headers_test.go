package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

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

type test1xxResponseWriter struct {
	header      http.Header
	statusCodes []int
	written     [][]byte
}

func newTest1xxResponseWriter() *test1xxResponseWriter {
	return &test1xxResponseWriter{
		header: make(http.Header),
	}
}

func (w *test1xxResponseWriter) Header() http.Header {
	return w.header
}

func (w *test1xxResponseWriter) WriteHeader(statusCode int) {
	w.statusCodes = append(w.statusCodes, statusCode)
}

func (w *test1xxResponseWriter) Write(b []byte) (int, error) {
	w.written = append(w.written, append([]byte(nil), b...))
	return len(b), nil
}

func Test1xxResponseHeaderPreservation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.Header().Set("X-1xx-Only", "1xx-value")
		w.WriteHeader(http.StatusEarlyHints) // 103

		// Backend clears 1xx headers before 200 OK response
		w.Header().Del("Link")
		w.Header().Del("X-1xx-Only")

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	h := &Handler{
		logger: zap.NewNop(),
		Upstreams: UpstreamPool{
			{
				Dial: backendURL.Host,
				Host: new(Host),
			},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RoundRobinSelection{},
		},
		Transport: testTransport{&http.Transport{}},
	}

	req := httptest.NewRequest("GET", "/", nil)
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	server := &caddyhttp.Server{
		Logs: &caddyhttp.ServerLogConfig{},
	}
	ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, server)
	req = req.WithContext(ctx)

	rw := newTest1xxResponseWriter()
	// Outer middleware sets headers prior to reverse proxying
	rw.Header().Set("X-Outer-Middleware", "outer-value")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	err = h.ServeHTTP(rw, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rw.statusCodes) < 2 {
		t.Fatalf("expected at least 2 WriteHeader calls (1xx and 200), got %v", rw.statusCodes)
	}
	if rw.statusCodes[0] != http.StatusEarlyHints {
		t.Errorf("first WriteHeader status = %d, want %d", rw.statusCodes[0], http.StatusEarlyHints)
	}
	if rw.statusCodes[1] != http.StatusOK {
		t.Errorf("second WriteHeader status = %d, want %d", rw.statusCodes[1], http.StatusOK)
	}

	// Outer middleware headers must persist in final response header map
	if got := rw.Header().Get("X-Outer-Middleware"); got != "outer-value" {
		t.Errorf("X-Outer-Middleware = %q, want %q", got, "outer-value")
	}
	if got := rw.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}

	// 1xx headers from backend must NOT leak into final response header map
	if got := rw.Header().Get("X-1xx-Only"); got != "" {
		t.Errorf("X-1xx-Only should not leak into final response headers, got %q", got)
	}
	if got := rw.Header().Get("Link"); got != "" {
		t.Errorf("Link header from 1xx should not leak into final response headers, got %q", got)
	}
}
