package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httptest"
	"net/textproto"
	"strings"
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

type mock1xxTransport struct {
	responses []struct {
		code   int
		header textproto.MIMEHeader
	}
	finalHeader http.Header
	finalStatus int
}

func (m *mock1xxTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.Got1xxResponse != nil {
		for _, resp := range m.responses {
			if err := trace.Got1xxResponse(resp.code, resp.header); err != nil {
				return nil, err
			}
		}
	}
	status := m.finalStatus
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     m.finalHeader,
		Body:       io.NopCloser(strings.NewReader("OK")),
		Request:    req,
	}, nil
}

type responseSnapshot struct {
	statusCode int
	headers    http.Header
}

type trackingResponseWriter struct {
	*httptest.ResponseRecorder
	snapshots []responseSnapshot
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.snapshots = append(w.snapshots, responseSnapshot{
		statusCode: code,
		headers:    w.Header().Clone(),
	})
	w.ResponseRecorder.WriteHeader(code)
}

func Test1xxResponseDownstreamHeaderPreservation(t *testing.T) {
	mockTrans := &mock1xxTransport{
		responses: []struct {
			code   int
			header textproto.MIMEHeader
		}{
			{
				code: 103,
				header: textproto.MIMEHeader{
					"Link": []string{"</style.css>; rel=preload"},
				},
			},
		},
		finalHeader: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: mockTrans,
		Upstreams: []*Upstream{{Host: new(Host), Dial: "127.0.0.1:80"}},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RoundRobinSelection{},
		},
	}

	rec := &trackingResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	rec.Header().Set("Access-Control-Allow-Origin", "*")
	rec.Header().Set("X-Trace-ID", "trace-123")

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// We expect two WriteHeader calls: one for 103 Early Hints, one for 200 OK.
	if len(rec.snapshots) != 2 {
		t.Fatalf("expected 2 WriteHeader snapshots, got %d", len(rec.snapshots))
	}

	// 103 Early Hints snapshot checks
	snap103 := rec.snapshots[0]
	if snap103.statusCode != 103 {
		t.Errorf("snapshot 0 status = %d, want 103", snap103.statusCode)
	}
	if got := snap103.headers.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("snapshot 0 Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if got := snap103.headers.Get("X-Trace-ID"); got != "trace-123" {
		t.Errorf("snapshot 0 X-Trace-ID = %q, want %q", got, "trace-123")
	}
	if got := snap103.headers.Get("Link"); got != "</style.css>; rel=preload" {
		t.Errorf("snapshot 0 Link = %q, want %q", got, "</style.css>; rel=preload")
	}

	// 200 OK snapshot checks
	snap200 := rec.snapshots[1]
	if snap200.statusCode != 200 {
		t.Errorf("snapshot 1 status = %d, want 200", snap200.statusCode)
	}
	if got := snap200.headers.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("snapshot 1 Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if got := snap200.headers.Get("X-Trace-ID"); got != "trace-123" {
		t.Errorf("snapshot 1 X-Trace-ID = %q, want %q", got, "trace-123")
	}
	if got := snap200.headers.Get("Content-Type"); got != "text/html" {
		t.Errorf("snapshot 1 Content-Type = %q, want %q", got, "text/html")
	}
	if got := snap200.headers.Get("Link"); got != "" {
		t.Errorf("snapshot 1 Link should be cleared, got %q", got)
	}

	// Check final ResponseWriter header map after completion
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("final rec.Header() Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if got := rec.Header().Get("X-Trace-ID"); got != "trace-123" {
		t.Errorf("final rec.Header() X-Trace-ID = %q, want %q", got, "trace-123")
	}
	if got := rec.Header().Get("Link"); got != "" {
		t.Errorf("final rec.Header() Link should be empty, got %q", got)
	}
}

func Test1xxSequentialResponseHeaderPreservation(t *testing.T) {
	mockTrans := &mock1xxTransport{
		responses: []struct {
			code   int
			header textproto.MIMEHeader
		}{
			{
				code: 100,
				header: textproto.MIMEHeader{
					"X-100-Header": []string{"continue"},
				},
			},
			{
				code: 103,
				header: textproto.MIMEHeader{
					"Link": []string{"</script.js>; rel=preload"},
				},
			},
		},
		finalHeader: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: mockTrans,
		Upstreams: []*Upstream{{Host: new(Host), Dial: "127.0.0.1:80"}},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RoundRobinSelection{},
		},
	}

	rec := &trackingResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	rec.Header().Set("X-Outer-Middleware", "active")

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// 100, 103, 200 = 3 snapshots
	if len(rec.snapshots) != 3 {
		t.Fatalf("expected 3 WriteHeader snapshots, got %d", len(rec.snapshots))
	}

	// 100 Continue
	if got := rec.snapshots[0].headers.Get("X-Outer-Middleware"); got != "active" {
		t.Errorf("snap 0 X-Outer-Middleware = %q, want %q", got, "active")
	}
	if got := rec.snapshots[0].headers.Get("X-100-Header"); got != "continue" {
		t.Errorf("snap 0 X-100-Header = %q, want %q", got, "continue")
	}

	// 103 Early Hints
	if got := rec.snapshots[1].headers.Get("X-Outer-Middleware"); got != "active" {
		t.Errorf("snap 1 X-Outer-Middleware = %q, want %q", got, "active")
	}
	if got := rec.snapshots[1].headers.Get("Link"); got != "</script.js>; rel=preload" {
		t.Errorf("snap 1 Link = %q, want %q", got, "</script.js>; rel=preload")
	}
	if got := rec.snapshots[1].headers.Get("X-100-Header"); got != "" {
		t.Errorf("snap 1 X-100-Header should be cleared, got %q", got)
	}

	// 200 OK
	if got := rec.snapshots[2].headers.Get("X-Outer-Middleware"); got != "active" {
		t.Errorf("snap 2 X-Outer-Middleware = %q, want %q", got, "active")
	}
	if got := rec.snapshots[2].headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("snap 2 Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.snapshots[2].headers.Get("X-100-Header"); got != "" {
		t.Errorf("snap 2 X-100-Header should be cleared, got %q", got)
	}
	if got := rec.snapshots[2].headers.Get("Link"); got != "" {
		t.Errorf("snap 2 Link should be cleared, got %q", got)
	}
}
