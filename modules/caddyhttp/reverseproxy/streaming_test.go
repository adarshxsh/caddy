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

type mockFlushWriter struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	flushCount int
}

func (m *mockFlushWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func (m *mockFlushWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCount++
	return nil
}

func (m *mockFlushWriter) Flushes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCount
}

func (m *mockFlushWriter) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}

func TestH2ReadWriteCloserDelayedFlush(t *testing.T) {
	mock := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     mock,
		flush:   mock.Flush,
		latency: 50 * time.Millisecond,
		logger:  caddy.Log(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(bytes.NewReader(nil)),
		writer:     mlw,
	}

	_, _ = rwc.Write([]byte("hello"))
	_, _ = rwc.Write([]byte("world"))

	if mock.Flushes() != 0 {
		t.Fatalf("expected 0 flushes immediately after rapid writes, got %d", mock.Flushes())
	}

	time.Sleep(100 * time.Millisecond)

	if mock.Flushes() != 1 {
		t.Fatalf("expected 1 flush after latency window, got %d", mock.Flushes())
	}

	if mock.String() != "helloworld" {
		t.Fatalf("got output %q, want %q", mock.String(), "helloworld")
	}

	_ = rwc.Close()
}

func TestH2ReadWriteCloserImmediateFlush(t *testing.T) {
	mock := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     mock,
		flush:   mock.Flush,
		latency: -1,
		logger:  caddy.Log(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(bytes.NewReader(nil)),
		writer:     mlw,
	}

	_, _ = rwc.Write([]byte("a"))
	if mock.Flushes() != 1 {
		t.Fatalf("expected 1 flush, got %d", mock.Flushes())
	}

	_, _ = rwc.Write([]byte("b"))
	if mock.Flushes() != 2 {
		t.Fatalf("expected 2 flushes, got %d", mock.Flushes())
	}

	_ = rwc.Close()
}

func TestH2ReadWriteCloserCloseFlushesPending(t *testing.T) {
	mock := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     mock,
		flush:   mock.Flush,
		latency: 10 * time.Second,
		logger:  caddy.Log(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(bytes.NewReader(nil)),
		writer:     mlw,
	}

	_, _ = rwc.Write([]byte("pending data"))
	if mock.Flushes() != 0 {
		t.Fatalf("expected 0 flushes before close, got %d", mock.Flushes())
	}

	err := rwc.Close()
	if err != nil {
		t.Fatalf("unexpected error on Close: %v", err)
	}

	if mock.Flushes() != 1 {
		t.Fatalf("expected 1 flush on close, got %d", mock.Flushes())
	}
	if mock.String() != "pending data" {
		t.Fatalf("got output %q, want %q", mock.String(), "pending data")
	}
}

func TestHandleUpgradeResponseH2FlushInterval(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flushInterval caddy.Duration
	}{
		{
			name:          "default 0 maps to 10ms",
			flushInterval: 0,
		},
		{
			name:          "positive duration 50ms",
			flushInterval: caddy.Duration(50 * time.Millisecond),
		},
		{
			name:          "negative duration -1 maps to immediate",
			flushInterval: -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				FlushInterval: tc.flushInterval,
			}
			req := httptest.NewRequest("CONNECT", "/ws", nil)
			ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
				"extended_connect_websocket_body": io.NopCloser(strings.NewReader("")),
			})
			req = req.WithContext(ctx)

			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")

			res := &http.Response{
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader("")),
			}
			res.Header.Set("Upgrade", "websocket")

			rw := httptest.NewRecorder()

			var wg sync.WaitGroup
			h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
			wg.Wait()

			if rw.Code != http.StatusOK {
				t.Fatalf("expected status 200 OK, got %d", rw.Code)
			}
		})
	}
}
