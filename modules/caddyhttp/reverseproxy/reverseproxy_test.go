package reverseproxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type recordingResponseWriter struct {
	header           http.Header
	statusCodes      []int
	headersSnapshots []http.Header
	body             bytes.Buffer
}

func newRecordingResponseWriter() *recordingResponseWriter {
	return &recordingResponseWriter{
		header: make(http.Header),
	}
}

func (w *recordingResponseWriter) Header() http.Header {
	return w.header
}

func (w *recordingResponseWriter) WriteHeader(statusCode int) {
	w.statusCodes = append(w.statusCodes, statusCode)
	snapshot := make(http.Header)
	for k, vv := range w.header {
		vvCopy := make([]string, len(vv))
		copy(vvCopy, vv)
		snapshot[k] = vvCopy
	}
	w.headersSnapshots = append(w.headersSnapshots, snapshot)
}

func (w *recordingResponseWriter) Write(b []byte) (int, error) {
	if len(w.statusCodes) == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func Test1xxHeaderIsolation(t *testing.T) {
	// Start a backend TCP server that emits a 103 Early Hints informational response
	// followed by a final 200 OK response.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)

		// Send 103 Early Hints
		conn.Write([]byte("HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"))
		time.Sleep(20 * time.Millisecond)

		// Send final 200 OK
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"))
	}()

	u := &Upstream{Dial: l.Addr().String()}
	tp := &HTTPTransport{}
	_ = tp.Provision(caddy.Context{})
	h := &Handler{
		Transport:     tp,
		Upstreams:     UpstreamPool{u},
		LoadBalancing: &LoadBalancing{SelectionPolicy: RandomSelection{}},
		logger:        zap.NewNop(),
	}
	h.provisionUpstream(u, false)

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	server := &caddyhttp.Server{}
	vars := map[string]any{
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, server)
	ctx = context.WithValue(ctx, caddy.CtxKey("replacer"), caddy.NewReplacer())
	req = req.WithContext(ctx)

	rw := newRecordingResponseWriter()
	// Simulate outer middleware setting headers prior to proxy execution
	rw.Header().Set("X-Outer-Middleware", "preserved-value")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	err = h.ServeHTTP(rw, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Verify status codes written
	if len(rw.statusCodes) < 2 {
		t.Fatalf("expected at least 2 status codes (103 and 200), got %v", rw.statusCodes)
	}
	if rw.statusCodes[0] != 103 {
		t.Errorf("expected first status code 103, got %d", rw.statusCodes[0])
	}
	if rw.statusCodes[1] != 200 {
		t.Errorf("expected second status code 200, got %d", rw.statusCodes[1])
	}

	// 103 Early Hints frame snapshot should include both outer middleware headers AND 103 Link header
	snap103 := rw.headersSnapshots[0]
	if got := snap103.Get("X-Outer-Middleware"); got != "preserved-value" {
		t.Errorf("103 snapshot missing X-Outer-Middleware, got %q", got)
	}
	if got := snap103.Get("Link"); got != "</style.css>; rel=preload" {
		t.Errorf("103 snapshot missing Link header, got %q", got)
	}

	// Final 200 OK frame snapshot should include outer middleware headers AND 200 Content-Type header,
	// but NOT the 103 Link header
	snap200 := rw.headersSnapshots[1]
	if got := snap200.Get("X-Outer-Middleware"); got != "preserved-value" {
		t.Errorf("200 snapshot missing outer header X-Outer-Middleware, got %q", got)
	}
	if got := snap200.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("200 snapshot missing outer header Access-Control-Allow-Origin, got %q", got)
	}
	if got := snap200.Get("Content-Type"); got != "text/plain" {
		t.Errorf("200 snapshot missing Content-Type, got %q", got)
	}
	if got := snap200.Get("Link"); got != "" {
		t.Errorf("200 snapshot leaked 1xx Link header, got %q", got)
	}

	// Verify final response writer header state
	finalHeaders := rw.Header()
	if got := finalHeaders.Get("X-Outer-Middleware"); got != "preserved-value" {
		t.Errorf("final headers missing X-Outer-Middleware, got %q", got)
	}
	if got := finalHeaders.Get("Link"); got != "" {
		t.Errorf("final headers leaked Link header, got %q", got)
	}
}

func Test1xxHeaderIsolationOverlappingKey(t *testing.T) {
	// Test matching key names between 1xx responses and outer middleware
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)

		// Send 100 Continue with overlapping header
		conn.Write([]byte("HTTP/1.1 100 Continue\r\nX-Overlapping: 1xx-value\r\n\r\n"))
		time.Sleep(20 * time.Millisecond)

		// Send final 200 OK
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"))
	}()

	u := &Upstream{Dial: l.Addr().String()}
	tp := &HTTPTransport{}
	_ = tp.Provision(caddy.Context{})
	h := &Handler{
		Transport:     tp,
		Upstreams:     UpstreamPool{u},
		LoadBalancing: &LoadBalancing{SelectionPolicy: RandomSelection{}},
		logger:        zap.NewNop(),
	}
	h.provisionUpstream(u, false)

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	server := &caddyhttp.Server{}
	vars := map[string]any{
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, server)
	ctx = context.WithValue(ctx, caddy.CtxKey("replacer"), caddy.NewReplacer())
	req = req.WithContext(ctx)

	rw := newRecordingResponseWriter()
	rw.Header().Set("X-Outer-Header", "keep-me")
	rw.Header().Set("X-Overlapping", "outer-value")

	err = h.ServeHTTP(rw, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Final headers should keep non-overlapping outer header, but remove overlapping header key
	finalHeaders := rw.Header()
	if got := finalHeaders.Get("X-Outer-Header"); got != "keep-me" {
		t.Errorf("expected X-Outer-Header = keep-me, got %q", got)
	}
	if got := finalHeaders.Get("X-Overlapping"); got != "" {
		t.Errorf("expected overlapping header to be removed after 1xx flush, got %q", got)
	}
}

func Benchmark1xxHeaderDeletion(b *testing.B) {
	header1xx := http.Header{
		"Link":   []string{"</style.css>; rel=preload"},
		"X-1xx":  []string{"val1", "val2"},
		"Server": []string{"upstream-server"},
	}

	h := http.Header{
		"X-Outer-Middleware":          []string{"outer-val"},
		"Access-Control-Allow-Origin": []string{"*"},
		"Link":                        []string{"</style.css>; rel=preload"},
		"X-1xx":                       []string{"val1", "val2"},
		"Server":                      []string{"upstream-server"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for k := range header1xx {
			h.Del(k)
		}
	}
}
