package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
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
	header    http.Header
	flushes   []trackedFlush
	status    int
	wroteBody []byte
}

type trackedFlush struct {
	code   int
	header http.Header
}

func newTrackingResponseWriter() *trackingResponseWriter {
	return &trackingResponseWriter{
		header: make(http.Header),
	}
}

func (w *trackingResponseWriter) Header() http.Header {
	return w.header
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.flushes = append(w.flushes, trackedFlush{
		code:   code,
		header: w.header.Clone(),
	})
}

func (w *trackingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.wroteBody = append(w.wroteBody, b...)
	return len(b), nil
}

type mock1xxRoundTripper struct {
	informationalCode   int
	informationalHeader textproto.MIMEHeader
	finalStatusCode     int
	finalHeader         http.Header
}

func (rt mock1xxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.Got1xxResponse != nil {
		err := trace.Got1xxResponse(rt.informationalCode, rt.informationalHeader)
		if err != nil {
			return nil, err
		}
	}
	return &http.Response{
		StatusCode: rt.finalStatusCode,
		Header:     rt.finalHeader,
		Body:       io.NopCloser(strings.NewReader("final response body")),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}, nil
}

func Test1xxResponsePreservesOuterHeaders(t *testing.T) {
	rt := mock1xxRoundTripper{
		informationalCode: 103,
		informationalHeader: textproto.MIMEHeader{
			"X-1xx-Header": []string{"1xx-value"},
		},
		finalStatusCode: 200,
		finalHeader: http.Header{
			"X-Final-Header": []string{"final-value"},
		},
	}

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: rt,
	}

	w := newTrackingResponseWriter()
	w.Header().Set("X-Outer-Header", "outer-value")
	w.Header().Set("X-Tracing-ID", "12345")

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	di := DialInfo{
		Upstream: &Upstream{
			Host: new(Host),
		},
	}
	err := h.reverseProxy(w, req, req, caddy.NewReplacer(), di, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(w.flushes) != 2 {
		t.Fatalf("expected 2 flushes (103 1xx and 200 final), got %d", len(w.flushes))
	}

	// 1xx Informational Flush
	flush1xx := w.flushes[0]
	if flush1xx.code != 103 {
		t.Errorf("informational status = %d, want 103", flush1xx.code)
	}
	if got := flush1xx.header.Get("X-Outer-Header"); got != "outer-value" {
		t.Errorf("informational flush X-Outer-Header = %q, want %q", got, "outer-value")
	}
	if got := flush1xx.header.Get("X-Tracing-ID"); got != "12345" {
		t.Errorf("informational flush X-Tracing-ID = %q, want %q", got, "12345")
	}
	if got := flush1xx.header.Get("X-1xx-Header"); got != "1xx-value" {
		t.Errorf("informational flush X-1xx-Header = %q, want %q", got, "1xx-value")
	}

	// Final Response Flush
	flushFinal := w.flushes[1]
	if flushFinal.code != 200 {
		t.Errorf("final response status = %d, want 200", flushFinal.code)
	}
	if got := flushFinal.header.Get("X-Outer-Header"); got != "outer-value" {
		t.Errorf("final response X-Outer-Header = %q, want %q", got, "outer-value")
	}
	if got := flushFinal.header.Get("X-Tracing-ID"); got != "12345" {
		t.Errorf("final response X-Tracing-ID = %q, want %q", got, "12345")
	}
	if got := flushFinal.header.Get("X-Final-Header"); got != "final-value" {
		t.Errorf("final response X-Final-Header = %q, want %q", got, "final-value")
	}
	if got := flushFinal.header.Get("X-1xx-Header"); got != "" {
		t.Errorf("final response X-1xx-Header = %q, want empty (1xx header leaked)", got)
	}
}

type mockMulti1xxRoundTripper struct {
	informationalResponses []struct {
		code   int
		header textproto.MIMEHeader
	}
	finalStatusCode int
	finalHeader     http.Header
}

func (rt mockMulti1xxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.Got1xxResponse != nil {
		for _, info := range rt.informationalResponses {
			err := trace.Got1xxResponse(info.code, info.header)
			if err != nil {
				return nil, err
			}
		}
	}
	return &http.Response{
		StatusCode: rt.finalStatusCode,
		Header:     rt.finalHeader,
		Body:       io.NopCloser(strings.NewReader("final response body")),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}, nil
}

func TestMultiple1xxResponsesPreservesOuterHeaders(t *testing.T) {
	rt := mockMulti1xxRoundTripper{
		informationalResponses: []struct {
			code   int
			header textproto.MIMEHeader
		}{
			{
				code: 100,
				header: textproto.MIMEHeader{
					"X-100-Header": []string{"100-value"},
				},
			},
			{
				code: 103,
				header: textproto.MIMEHeader{
					"X-103-Header": []string{"103-value"},
				},
			},
		},
		finalStatusCode: 200,
		finalHeader: http.Header{
			"X-Final-Header": []string{"final-value"},
		},
	}

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: rt,
	}

	w := newTrackingResponseWriter()
	w.Header().Set("X-Outer-Header", "outer-value")

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	di := DialInfo{
		Upstream: &Upstream{
			Host: new(Host),
		},
	}
	err := h.reverseProxy(w, req, req, caddy.NewReplacer(), di, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(w.flushes) != 3 {
		t.Fatalf("expected 3 flushes (100, 103, and 200), got %d", len(w.flushes))
	}

	// Flush 1: 100
	f1 := w.flushes[0]
	if f1.code != 100 || f1.header.Get("X-Outer-Header") != "outer-value" || f1.header.Get("X-100-Header") != "100-value" {
		t.Errorf("flush 1 error: code=%d, outer=%q, 100=%q", f1.code, f1.header.Get("X-Outer-Header"), f1.header.Get("X-100-Header"))
	}

	// Flush 2: 103
	f2 := w.flushes[1]
	if f2.code != 103 || f2.header.Get("X-Outer-Header") != "outer-value" || f2.header.Get("X-103-Header") != "103-value" {
		t.Errorf("flush 2 error: code=%d, outer=%q, 103=%q", f2.code, f2.header.Get("X-Outer-Header"), f2.header.Get("X-103-Header"))
	}
	if f2.header.Get("X-100-Header") != "" {
		t.Errorf("100 header leaked into 103 flush: %q", f2.header.Get("X-100-Header"))
	}

	// Flush 3: 200
	f3 := w.flushes[2]
	if f3.code != 200 || f3.header.Get("X-Outer-Header") != "outer-value" || f3.header.Get("X-Final-Header") != "final-value" {
		t.Errorf("flush 3 error: code=%d, outer=%q, final=%q", f3.code, f3.header.Get("X-Outer-Header"), f3.header.Get("X-Final-Header"))
	}
	if f3.header.Get("X-100-Header") != "" || f3.header.Get("X-103-Header") != "" {
		t.Errorf("1xx headers leaked into final flush: 100=%q, 103=%q", f3.header.Get("X-100-Header"), f3.header.Get("X-103-Header"))
	}
}
