package reverseproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHandlerCopyResponse(t *testing.T) {
	h := Handler{}
	testdata := []string{
		"",
		strings.Repeat("a", defaultBufferSize),
		strings.Repeat("123456789 123456789 123456789 12", 3000),
	}

	dst := bytes.NewBuffer(nil)
	recorder := httptest.NewRecorder()
	recorder.Body = dst

	for _, d := range testdata {
		src := bytes.NewBuffer([]byte(d))
		dst.Reset()
		err := h.copyResponse(recorder, src, 0, caddy.Log())
		if err != nil {
			t.Errorf("failed with error: %v", err)
		}
		out := dst.String()
		if out != d {
			t.Errorf("bad read: got %q", out)
		}
	}
}

func TestSwitchProtocolCopierBufferSize(t *testing.T) {
	var wg sync.WaitGroup
	var errc = make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 7,
	}

	buf := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "hello" {
		t.Fatalf("copied data = %q, want %q", got, "hello")
	}
}

func TestSwitchProtocolCopierDefaultBufferSize(t *testing.T) {
	copier := switchProtocolCopier{}
	buf := copier.buffer()
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

func TestH2ReadWriteCloserWriteNoFlush(t *testing.T) {
	rec := newMockFlushingResponseWriter()
	rwc := h2ReadWriteCloser{
		ReadCloser:     io.NopCloser(bytes.NewReader(nil)),
		ResponseWriter: rec,
	}

	n, err := rwc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.flushes != 0 {
		t.Fatalf("expected 0 flushes from h2ReadWriteCloser.Write, got %d", rec.flushes)
	}
	if rec.buf.String() != "hello" {
		t.Fatalf("expected 'hello' in buffer, got %q", rec.buf.String())
	}
}

func TestMaxLatencyWriterResponseWriter(t *testing.T) {
	rec := newMockFlushingResponseWriter()
	mlw := &maxLatencyWriter{
		dst:     rec,
		flush:   func() error { rec.Flush(); return nil },
		latency: -1,
		logger:  zap.NewNop(),
	}

	mlw.Header().Set("X-Test", "value")
	if rec.Header().Get("X-Test") != "value" {
		t.Fatalf("Header() delegation failed")
	}

	mlw.WriteHeader(200)
	if rec.code != 200 {
		t.Fatalf("WriteHeader() delegation failed")
	}

	n, err := mlw.Write([]byte("data"))
	if err != nil || n != 4 {
		t.Fatalf("Write failed: %v, %d", err, n)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.flushes != 1 {
		t.Fatalf("expected 1 immediate flush for latency < 0, got %d", rec.flushes)
	}
}

func TestHandleUpgradeResponseExtendedConnect(t *testing.T) {
	t.Run("default 10ms flush interval", func(t *testing.T) {
		h := &Handler{
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		clientPipeR, clientPipeW := io.Pipe()
		defer clientPipeR.Close()
		defer clientPipeW.Close()

		vars := map[string]any{
			"extended_connect_websocket_body": clientPipeR,
		}
		ctx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, vars)

		req := httptest.NewRequest("CONNECT", "/ws", nil).WithContext(ctx)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
		}
		res.Header.Set("Upgrade", "websocket")
		res.Header.Set("Connection", "Upgrade")

		backendPipeR, backendPipeW := io.Pipe()
		res.Body = struct {
			io.Reader
			io.Writer
			io.Closer
		}{
			Reader: backendPipeR,
			Writer: io.Discard,
			Closer: backendPipeR,
		}

		rec := newMockFlushingResponseWriter()
		var wg sync.WaitGroup

		done := make(chan struct{})
		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rec, req, res)
			close(done)
		}()

		// Send data from backend
		go func() {
			time.Sleep(10 * time.Millisecond)
			_, _ = backendPipeW.Write([]byte("backend payload"))
			time.Sleep(30 * time.Millisecond)
			backendPipeW.Close()
			clientPipeW.Close()
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleUpgradeResponse timed out")
		}

		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.buf.String() != "backend payload" {
			t.Fatalf("expected 'backend payload', got %q", rec.buf.String())
		}
		if rec.flushes < 2 { // 1 for initial OK header, at least 1 for data flush
			t.Fatalf("expected at least 2 flushes (1 header + 1 delayed data), got %d", rec.flushes)
		}
	})

	t.Run("flush interval -1 immediate flush", func(t *testing.T) {
		h := &Handler{
			FlushInterval: caddy.Duration(-1),
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		clientPipeR, clientPipeW := io.Pipe()
		defer clientPipeR.Close()
		defer clientPipeW.Close()

		vars := map[string]any{
			"extended_connect_websocket_body": clientPipeR,
		}
		ctx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, vars)

		req := httptest.NewRequest("CONNECT", "/ws", nil).WithContext(ctx)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
		}
		res.Header.Set("Upgrade", "websocket")
		res.Header.Set("Connection", "Upgrade")

		backendPipeR, backendPipeW := io.Pipe()
		res.Body = struct {
			io.Reader
			io.Writer
			io.Closer
		}{
			Reader: backendPipeR,
			Writer: io.Discard,
			Closer: backendPipeR,
		}

		rec := newMockFlushingResponseWriter()
		var wg sync.WaitGroup

		done := make(chan struct{})
		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rec, req, res)
			close(done)
		}()

		go func() {
			time.Sleep(10 * time.Millisecond)
			_, _ = backendPipeW.Write([]byte("immediate1"))
			_, _ = backendPipeW.Write([]byte("immediate2"))
			backendPipeW.Close()
			clientPipeW.Close()
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleUpgradeResponse timed out")
		}

		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.buf.String() != "immediate1immediate2" {
			t.Fatalf("expected 'immediate1immediate2', got %q", rec.buf.String())
		}
		// Initial 1 header flush + at least 2 data write flushes = >=3
		if rec.flushes < 3 {
			t.Fatalf("expected at least 3 flushes for immediate mode, got %d", rec.flushes)
		}
	})
}

type mockFlushingResponseWriter struct {
	header  http.Header
	buf     bytes.Buffer
	mu      sync.Mutex
	flushes int
	writes  int
	code    int
}

func newMockFlushingResponseWriter() *mockFlushingResponseWriter {
	return &mockFlushingResponseWriter{
		header: make(http.Header),
	}
}

func (m *mockFlushingResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockFlushingResponseWriter) WriteHeader(code int) {
	m.code = code
}

func (m *mockFlushingResponseWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	return m.buf.Write(p)
}

func (m *mockFlushingResponseWriter) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushes++
}
