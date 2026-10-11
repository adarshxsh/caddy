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

type informationalResponse struct {
	Code   int
	Header http.Header
}

type test1xxRecorder struct {
	header       http.Header
	responses1xx []informationalResponse
	finalCode    int
	finalHeader  http.Header
	body         []byte
}

func newTest1xxRecorder() *test1xxRecorder {
	return &test1xxRecorder{
		header: make(http.Header),
	}
}

func (r *test1xxRecorder) Header() http.Header {
	return r.header
}

func (r *test1xxRecorder) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		r.responses1xx = append(r.responses1xx, informationalResponse{
			Code:   code,
			Header: r.header.Clone(),
		})
		return
	}
	if r.finalCode == 0 {
		r.finalCode = code
		r.finalHeader = r.header.Clone()
	}
}

func (r *test1xxRecorder) Write(b []byte) (int, error) {
	if r.finalCode == 0 {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

func TestPreserveOuterHeadersAcross1xxResponse(t *testing.T) {
	// Create backend server that sends a 103 Early Hints response followed by a 200 OK response.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(103)

		// Backend removes 103 headers so they aren't part of the final 200 OK response header block
		w.Header().Del("Link")
		w.Header().Set("X-Backend-Header", "backend-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	handler := &Handler{
		Upstreams: UpstreamPool{
			{Dial: backendURL.Host, Host: new(Host)},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
		Transport: &HTTPTransport{
			Transport: &http.Transport{},
		},
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	req = req.WithContext(ctx)

	rec := newTest1xxRecorder()
	// Simulate outer middleware setting headers prior to reverse_proxy
	rec.Header().Set("X-Outer-Header", "outer-value")
	rec.Header().Set("Access-Control-Allow-Origin", "*")

	err = handler.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned unexpected error: %v", err)
	}

	// Verify 1xx response was recorded with outer headers and backend 1xx headers
	if len(rec.responses1xx) != 1 {
		t.Fatalf("expected 1 informational response, got %d", len(rec.responses1xx))
	}
	if rec.responses1xx[0].Code != 103 {
		t.Errorf("1xx response code = %d; want 103", rec.responses1xx[0].Code)
	}
	if got := rec.responses1xx[0].Header.Get("Link"); got != "</style.css>; rel=preload" {
		t.Errorf("1xx response Link = %q; want %q", got, "</style.css>; rel=preload")
	}
	if got := rec.responses1xx[0].Header.Get("X-Outer-Header"); got != "outer-value" {
		t.Errorf("1xx response X-Outer-Header = %q; want %q", got, "outer-value")
	}

	// Verify final response status and headers
	if rec.finalCode != http.StatusOK {
		t.Errorf("final status code = %d; want 200", rec.finalCode)
	}
	if got := rec.finalHeader.Get("X-Outer-Header"); got != "outer-value" {
		t.Errorf("final X-Outer-Header = %q; want %q", got, "outer-value")
	}
	if got := rec.finalHeader.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("final Access-Control-Allow-Origin = %q; want %q", got, "*")
	}
	if got := rec.finalHeader.Get("X-Backend-Header"); got != "backend-value" {
		t.Errorf("final X-Backend-Header = %q; want %q", got, "backend-value")
	}
	if got := rec.finalHeader.Get("Link"); got != "" {
		t.Errorf("Link header should not be present in final response, got %q", got)
	}
}

func TestPreserveOuterHeadersAcrossMultiple1xxResponses(t *testing.T) {
	// Create backend server that sends 100 Continue, then 103 Early Hints, then 200 OK.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-100-Header", "val100")
		w.WriteHeader(100)
		w.Header().Del("X-100-Header")

		w.Header().Set("Link", "</script.js>; rel=preload")
		w.WriteHeader(103)
		w.Header().Del("Link")

		w.Header().Set("X-Final-Header", "final-val")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DONE"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	handler := &Handler{
		Upstreams: UpstreamPool{
			{Dial: backendURL.Host, Host: new(Host)},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
		Transport: &HTTPTransport{
			Transport: &http.Transport{},
		},
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	req = req.WithContext(ctx)

	rec := newTest1xxRecorder()
	rec.Header().Set("X-Request-ID", "req-12345")

	err = handler.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned unexpected error: %v", err)
	}

	if len(rec.responses1xx) != 2 {
		t.Fatalf("expected 2 1xx responses, got %d", len(rec.responses1xx))
	}
	if rec.responses1xx[0].Code != 100 {
		t.Errorf("first 1xx code = %d; want 100", rec.responses1xx[0].Code)
	}
	if rec.responses1xx[1].Code != 103 {
		t.Errorf("second 1xx code = %d; want 103", rec.responses1xx[1].Code)
	}

	if rec.finalCode != http.StatusOK {
		t.Errorf("final status code = %d; want 200", rec.finalCode)
	}
	if got := rec.finalHeader.Get("X-Request-ID"); got != "req-12345" {
		t.Errorf("final X-Request-ID = %q; want %q", got, "req-12345")
	}
	if got := rec.finalHeader.Get("X-Final-Header"); got != "final-val" {
		t.Errorf("final X-Final-Header = %q; want %q", got, "final-val")
	}
	if got := rec.finalHeader.Get("X-100-Header"); got != "" {
		t.Errorf("X-100-Header should not leak into final response, got %q", got)
	}
	if got := rec.finalHeader.Get("Link"); got != "" {
		t.Errorf("Link header should not leak into final response, got %q", got)
	}
}
