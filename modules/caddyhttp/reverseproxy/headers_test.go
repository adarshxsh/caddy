package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

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

type trackingResponseWriter struct {
	http.ResponseWriter
	writtenCodes   []int
	headersAtWrite []http.Header
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.writtenCodes = append(w.writtenCodes, code)
	hCopy := make(http.Header)
	for k, v := range w.Header() {
		vCopy := make([]string, len(v))
		copy(vCopy, v)
		hCopy[k] = vCopy
	}
	w.headersAtWrite = append(w.headersAtWrite, hCopy)
	w.ResponseWriter.WriteHeader(code)
}

func Test1xxResponseHeaderRestoration(t *testing.T) {
	t.Run("103 Early Hints", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Link", "</style.css>; rel=preload")
			w.Header().Set("X-1xx-Only", "early-value")
			w.WriteHeader(http.StatusEarlyHints)

			// Backend removes 1xx-specific headers before sending final 200 OK
			w.Header().Del("Link")
			w.Header().Del("X-1xx-Only")

			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Final-Header", "final-value")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}))
		defer ts.Close()

		upstreamURL, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatalf("failed to parse upstream URL: %v", err)
		}

		handler := &Handler{
			logger:    zap.NewNop(),
			Transport: testTransport{&http.Transport{}},
			Upstreams: []*Upstream{{
				Dial: upstreamURL.Host,
				Host: new(Host),
			}},
			LoadBalancing: &LoadBalancing{
				SelectionPolicy: &RandomSelection{},
			},
		}

		rec := httptest.NewRecorder()
		tracker := &trackingResponseWriter{
			ResponseWriter: rec,
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = prepareTestRequest(req)

		// Set outer middleware response headers before calling reverseproxy
		tracker.Header().Set("X-Outer-Middleware", "outer-value")
		tracker.Header().Set("X-1xx-Only", "outer-initial-1xx")

		err = handler.ServeHTTP(tracker, req, nil)
		if err != nil {
			t.Fatalf("unexpected handler error: %v", err)
		}

		// Verify 103 Early Hints flush
		if len(tracker.writtenCodes) < 2 {
			t.Fatalf("expected at least 2 status writes, got %d", len(tracker.writtenCodes))
		}
		if tracker.writtenCodes[0] != http.StatusEarlyHints {
			t.Errorf("expected first code %d, got %d", http.StatusEarlyHints, tracker.writtenCodes[0])
		}
		h103 := tracker.headersAtWrite[0]
		if got := h103.Get("X-Outer-Middleware"); got != "outer-value" {
			t.Errorf("103 flush X-Outer-Middleware = %q, want %q", got, "outer-value")
		}
		if got := h103.Get("Link"); got != "</style.css>; rel=preload" {
			t.Errorf("103 flush Link = %q, want %q", got, "</style.css>; rel=preload")
		}

		// Verify final 200 OK flush
		if tracker.writtenCodes[1] != http.StatusOK {
			t.Errorf("expected second code %d, got %d", http.StatusOK, tracker.writtenCodes[1])
		}
		h200 := tracker.headersAtWrite[1]
		if got := h200.Get("X-Outer-Middleware"); got != "outer-value" {
			t.Errorf("200 flush X-Outer-Middleware = %q, want %q", got, "outer-value")
		}
		if got := h200.Get("X-1xx-Only"); got != "outer-initial-1xx" {
			t.Errorf("200 flush X-1xx-Only = %q, want %q", got, "outer-initial-1xx")
		}
		if got := h200.Get("Link"); got != "" {
			t.Errorf("200 flush Link should be empty, got %q", got)
		}
		if got := h200.Get("X-Final-Header"); got != "final-value" {
			t.Errorf("200 flush X-Final-Header = %q, want %q", got, "final-value")
		}
	})

	t.Run("100 Continue", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-100-Header", "continue-value")
			w.WriteHeader(http.StatusContinue)

			w.Header().Del("X-100-Header")

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}))
		defer ts.Close()

		upstreamURL, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatalf("failed to parse upstream URL: %v", err)
		}

		handler := &Handler{
			logger:    zap.NewNop(),
			Transport: testTransport{&http.Transport{}},
			Upstreams: []*Upstream{{
				Dial: upstreamURL.Host,
				Host: new(Host),
			}},
			LoadBalancing: &LoadBalancing{
				SelectionPolicy: &RandomSelection{},
			},
		}

		rec := httptest.NewRecorder()
		tracker := &trackingResponseWriter{
			ResponseWriter: rec,
		}

		req := httptest.NewRequest("POST", "/", nil)
		req = prepareTestRequest(req)

		tracker.Header().Set("X-Request-Id", "req-123")

		err = handler.ServeHTTP(tracker, req, nil)
		if err != nil {
			t.Fatalf("unexpected handler error: %v", err)
		}

		if len(tracker.writtenCodes) < 2 {
			t.Fatalf("expected at least 2 status writes, got %d", len(tracker.writtenCodes))
		}
		if tracker.writtenCodes[0] != http.StatusContinue {
			t.Errorf("expected first code %d, got %d", http.StatusContinue, tracker.writtenCodes[0])
		}
		h100 := tracker.headersAtWrite[0]
		if got := h100.Get("X-Request-Id"); got != "req-123" {
			t.Errorf("100 flush X-Request-Id = %q, want %q", got, "req-123")
		}
		if got := h100.Get("X-100-Header"); got != "continue-value" {
			t.Errorf("100 flush X-100-Header = %q, want %q", got, "continue-value")
		}

		if tracker.writtenCodes[1] != http.StatusOK {
			t.Errorf("expected second code %d, got %d", http.StatusOK, tracker.writtenCodes[1])
		}
		h200 := tracker.headersAtWrite[1]
		if got := h200.Get("X-Request-Id"); got != "req-123" {
			t.Errorf("200 flush X-Request-Id = %q, want %q", got, "req-123")
		}
		if got := h200.Get("X-100-Header"); got != "" {
			t.Errorf("200 flush X-100-Header should be empty, got %q", got)
		}
	})

	t.Run("Multiple 1xx responses", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-100-Val", "val100")
			w.WriteHeader(http.StatusContinue)
			w.Header().Del("X-100-Val")

			w.Header().Set("Link", "</app.js>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("Link")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		}))
		defer ts.Close()

		upstreamURL, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatalf("failed to parse upstream URL: %v", err)
		}

		handler := &Handler{
			logger:    zap.NewNop(),
			Transport: testTransport{&http.Transport{}},
			Upstreams: []*Upstream{{
				Dial: upstreamURL.Host,
				Host: new(Host),
			}},
			LoadBalancing: &LoadBalancing{
				SelectionPolicy: &RandomSelection{},
			},
		}

		rec := httptest.NewRecorder()
		tracker := &trackingResponseWriter{
			ResponseWriter: rec,
		}

		req := httptest.NewRequest("POST", "/", nil)
		req = prepareTestRequest(req)

		tracker.Header().Set("X-Outer-Tracing", "trace-abc")

		err = handler.ServeHTTP(tracker, req, nil)
		if err != nil {
			t.Fatalf("unexpected handler error: %v", err)
		}

		if len(tracker.writtenCodes) < 3 {
			t.Fatalf("expected at least 3 status writes, got %d", len(tracker.writtenCodes))
		}
		if tracker.writtenCodes[0] != http.StatusContinue {
			t.Errorf("expected first code %d, got %d", http.StatusContinue, tracker.writtenCodes[0])
		}
		if tracker.writtenCodes[1] != http.StatusEarlyHints {
			t.Errorf("expected second code %d, got %d", http.StatusEarlyHints, tracker.writtenCodes[1])
		}
		if tracker.writtenCodes[2] != http.StatusOK {
			t.Errorf("expected third code %d, got %d", http.StatusOK, tracker.writtenCodes[2])
		}

		h100 := tracker.headersAtWrite[0]
		if got := h100.Get("X-Outer-Tracing"); got != "trace-abc" {
			t.Errorf("100 flush X-Outer-Tracing = %q, want %q", got, "trace-abc")
		}
		if got := h100.Get("X-100-Val"); got != "val100" {
			t.Errorf("100 flush X-100-Val = %q, want %q", got, "val100")
		}

		h103 := tracker.headersAtWrite[1]
		if got := h103.Get("X-Outer-Tracing"); got != "trace-abc" {
			t.Errorf("103 flush X-Outer-Tracing = %q, want %q", got, "trace-abc")
		}
		if got := h103.Get("Link"); got != "</app.js>; rel=preload" {
			t.Errorf("103 flush Link = %q, want %q", got, "</app.js>; rel=preload")
		}
		if got := h103.Get("X-100-Val"); got != "" {
			t.Errorf("103 flush X-100-Val should be empty, got %q", got)
		}

		h200 := tracker.headersAtWrite[2]
		if got := h200.Get("X-Outer-Tracing"); got != "trace-abc" {
			t.Errorf("200 flush X-Outer-Tracing = %q, want %q", got, "trace-abc")
		}
		if got := h200.Get("Content-Type"); got != "application/json" {
			t.Errorf("200 flush Content-Type = %q, want %q", got, "application/json")
		}
		if got := h200.Get("X-100-Val"); got != "" {
			t.Errorf("200 flush X-100-Val should be empty, got %q", got)
		}
		if got := h200.Get("Link"); got != "" {
			t.Errorf("200 flush Link should be empty, got %q", got)
		}
	})

	t.Run("Pre-existing header key overridden by 1xx and restored", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Overridden-Header", "1xx-temp-val")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("X-Overridden-Header")

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}))
		defer ts.Close()

		upstreamURL, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatalf("failed to parse upstream URL: %v", err)
		}

		handler := &Handler{
			logger:    zap.NewNop(),
			Transport: testTransport{&http.Transport{}},
			Upstreams: []*Upstream{{
				Dial: upstreamURL.Host,
				Host: new(Host),
			}},
			LoadBalancing: &LoadBalancing{
				SelectionPolicy: &RandomSelection{},
			},
		}

		rec := httptest.NewRecorder()
		tracker := &trackingResponseWriter{
			ResponseWriter: rec,
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = prepareTestRequest(req)

		tracker.Header().Set("X-Overridden-Header", "original-value")

		err = handler.ServeHTTP(tracker, req, nil)
		if err != nil {
			t.Fatalf("unexpected handler error: %v", err)
		}

		if len(tracker.writtenCodes) < 2 {
			t.Fatalf("expected at least 2 status writes, got %d", len(tracker.writtenCodes))
		}

		h200 := tracker.headersAtWrite[1]
		if got := h200.Get("X-Overridden-Header"); got != "original-value" {
			t.Errorf("200 flush X-Overridden-Header = %q, want %q", got, "original-value")
		}
	})
}
