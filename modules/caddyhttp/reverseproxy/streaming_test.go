package reverseproxy

import (
	"bytes"
	"context"
	"errors"
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
	flushErr   error
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
	return m.flushErr
}

func (m *mockFlushWriter) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCount
}

func (m *mockFlushWriter) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}

func TestH2ReadWriteCloserFlushIntervals(t *testing.T) {
	t.Run("Immediate flush on -1", func(t *testing.T) {
		fw := &mockFlushWriter{}
		mlw := &maxLatencyWriter{
			dst:     fw,
			flush:   fw.Flush,
			latency: -1,
			logger:  caddy.Log(),
		}
		rwc := h2ReadWriteCloser{w: mlw}

		_, err := rwc.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
		if got := fw.Count(); got != 1 {
			t.Fatalf("expected 1 immediate flush, got %d", got)
		}

		_, err = rwc.Write([]byte("world"))
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
		if got := fw.Count(); got != 2 {
			t.Fatalf("expected 2 immediate flushes, got %d", got)
		}
	})

	t.Run("Delayed flush on positive duration", func(t *testing.T) {
		fw := &mockFlushWriter{}
		mlw := &maxLatencyWriter{
			dst:     fw,
			flush:   fw.Flush,
			latency: 15 * time.Millisecond,
			logger:  caddy.Log(),
		}
		rwc := h2ReadWriteCloser{w: mlw}

		_, err := rwc.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
		if got := fw.Count(); got != 0 {
			t.Fatalf("expected 0 immediate flushes, got %d", got)
		}

		time.Sleep(30 * time.Millisecond)
		if got := fw.Count(); got != 1 {
			t.Fatalf("expected 1 delayed flush after timer, got %d", got)
		}
	})

	t.Run("Timer stopped on Close", func(t *testing.T) {
		fw := &mockFlushWriter{}
		mlw := &maxLatencyWriter{
			dst:     fw,
			flush:   fw.Flush,
			latency: 100 * time.Millisecond,
			logger:  caddy.Log(),
		}
		rwc := h2ReadWriteCloser{w: mlw}

		_, err := rwc.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}

		err = rwc.Close()
		if err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}

		time.Sleep(150 * time.Millisecond)
		if got := fw.Count(); got != 0 {
			t.Fatalf("expected 0 flushes because timer was stopped on Close, got %d", got)
		}
	})
}

func TestH2ReadWriteCloserFlushErrorHandling(t *testing.T) {
	t.Run("Immediate flush error returned on Write", func(t *testing.T) {
		expectedErr := errors.New("flush failed")
		fw := &mockFlushWriter{flushErr: expectedErr}
		mlw := &maxLatencyWriter{
			dst:     fw,
			flush:   fw.Flush,
			latency: -1,
			logger:  caddy.Log(),
		}
		rwc := h2ReadWriteCloser{w: mlw}

		_, err := rwc.Write([]byte("hello"))
		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("Delayed flush error returned on subsequent Write", func(t *testing.T) {
		expectedErr := errors.New("flush failed")
		fw := &mockFlushWriter{flushErr: expectedErr}
		mlw := &maxLatencyWriter{
			dst:     fw,
			flush:   fw.Flush,
			latency: 10 * time.Millisecond,
			logger:  caddy.Log(),
		}
		rwc := h2ReadWriteCloser{w: mlw}

		_, err := rwc.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("initial write should succeed, got %v", err)
		}

		time.Sleep(20 * time.Millisecond)

		_, err = rwc.Write([]byte("world"))
		if !errors.Is(err, expectedErr) {
			t.Fatalf("subsequent write should return stored flush error %v, got %v", expectedErr, err)
		}
	})
}

type mockResponseWriter struct {
	mu         sync.Mutex
	header     http.Header
	buf        bytes.Buffer
	status     int
	flushCount int
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{header: make(http.Header)}
}

func (m *mockResponseWriter) Header() http.Header { return m.header }

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = statusCode
}

func (m *mockResponseWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func (m *mockResponseWriter) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCount++
}

func (m *mockResponseWriter) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCount
}

func TestHandleUpgradeResponseH2Websocket(t *testing.T) {
	tests := []struct {
		name              string
		flushInterval     caddy.Duration
		expectedDelay     time.Duration
		expectedImmediate bool
	}{
		{
			name:              "FlushInterval -1 flushes immediately",
			flushInterval:     caddy.Duration(-1),
			expectedImmediate: true,
		},
		{
			name:          "FlushInterval 0 defaults to 2ms delay",
			flushInterval: caddy.Duration(0),
			expectedDelay: 2 * time.Millisecond,
		},
		{
			name:          "FlushInterval positive uses configured delay",
			flushInterval: caddy.Duration(20 * time.Millisecond),
			expectedDelay: 20 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				FlushInterval: tt.flushInterval,
				logger:        caddy.Log(),
				connections:   make(map[io.ReadWriteCloser]openConnection),
				connectionsMu: new(sync.Mutex),
			}

			rw := newMockResponseWriter()
			req := httptest.NewRequest("CONNECT", "/ws", strings.NewReader("client-data"))
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")

			vars := make(map[string]any)
			ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
			req = req.WithContext(ctx)
			caddyhttp.SetVar(req.Context(), "extended_connect_websocket_body", io.NopCloser(strings.NewReader("client-data")))

			res := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       nopReadWriteCloser{Reader: strings.NewReader("backend-data"), Writer: io.Discard},
			}
			res.Header.Set("Upgrade", "websocket")
			res.Header.Set("Connection", "Upgrade")

			var wg sync.WaitGroup
			h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)

			// Initial response headers flush should have occurred
			initialFlushes := rw.Count()
			if initialFlushes < 1 {
				t.Fatalf("expected at least 1 initial header flush, got %d", initialFlushes)
			}
		})
	}
}
