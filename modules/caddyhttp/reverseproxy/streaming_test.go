package reverseproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
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

type mockFlushingResponseWriter struct {
	http.ResponseWriter
	mu         sync.Mutex
	writeCount int
	flushCount int
	buf        bytes.Buffer
}

func (m *mockFlushingResponseWriter) Header() http.Header {
	return http.Header{}
}

func (m *mockFlushingResponseWriter) WriteHeader(statusCode int) {}

func (m *mockFlushingResponseWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCount++
	return m.buf.Write(p)
}

func (m *mockFlushingResponseWriter) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCount++
}

func (m *mockFlushingResponseWriter) counts() (writes, flushes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCount, m.flushCount
}

func TestH2ReadWriteCloserLatencyBounded(t *testing.T) {
	mockRW := &mockFlushingResponseWriter{}
	mlw := &maxLatencyWriter{
		dst:     mockRW,
		flush:   func() error { mockRW.Flush(); return nil },
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		writer:     mlw,
	}
	defer rwc.Close()

	// Perform consecutive rapid writes within the 50ms latency window
	for i := 0; i < 5; i++ {
		_, err := rwc.Write([]byte("data"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	writes, flushes := mockRW.counts()
	if writes != 5 {
		t.Errorf("expected 5 writes, got %d", writes)
	}
	if flushes != 0 {
		t.Errorf("expected 0 immediate flushes during rapid writes, got %d", flushes)
	}

	// Wait for delayed flush timer
	time.Sleep(100 * time.Millisecond)

	_, flushes = mockRW.counts()
	if flushes != 1 {
		t.Errorf("expected 1 aggregated flush after latency window, got %d", flushes)
	}
}

func TestH2ReadWriteCloserImmediateFlush(t *testing.T) {
	mockRW := &mockFlushingResponseWriter{}
	mlw := &maxLatencyWriter{
		dst:     mockRW,
		flush:   func() error { mockRW.Flush(); return nil },
		latency: -1,
		logger:  zap.NewNop(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		writer:     mlw,
	}
	defer rwc.Close()

	for i := 0; i < 3; i++ {
		_, err := rwc.Write([]byte("data"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	writes, flushes := mockRW.counts()
	if writes != 3 {
		t.Errorf("expected 3 writes, got %d", writes)
	}
	if flushes != 3 {
		t.Errorf("expected 3 immediate flushes for negative latency, got %d", flushes)
	}
}

func TestH2ReadWriteCloserFlushOnClose(t *testing.T) {
	mockRW := &mockFlushingResponseWriter{}
	mlw := &maxLatencyWriter{
		dst:     mockRW,
		flush:   func() error { mockRW.Flush(); return nil },
		latency: 10 * time.Second, // long latency so timer won't fire during test
		logger:  zap.NewNop(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		writer:     mlw,
	}

	_, err := rwc.Write([]byte("data"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	_, flushes := mockRW.counts()
	if flushes != 0 {
		t.Errorf("expected 0 flushes before close, got %d", flushes)
	}

	err = rwc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, flushes = mockRW.counts()
	if flushes != 1 {
		t.Errorf("expected 1 flush upon connection close, got %d", flushes)
	}
}
