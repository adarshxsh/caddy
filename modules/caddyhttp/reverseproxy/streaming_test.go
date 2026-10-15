package reverseproxy

import (
	"bytes"
	"io"
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

type mockFlushWriter struct {
	mu sync.Mutex
	bytes.Buffer
	flushCount int
}

func (m *mockFlushWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Buffer.Write(p)
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

func TestMaxLatencyWriter_ImmediateFlushAfterInterval(t *testing.T) {
	dst := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:       dst,
		flush:     dst.Flush,
		latency:   50 * time.Millisecond,
		lastFlush: time.Now().Add(-100 * time.Millisecond),
		logger:    zap.NewNop(),
	}

	n, err := mlw.Write([]byte("event data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 bytes written, got %d", n)
	}
	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected flush count to be 1, got %d", got)
	}
}

func TestMaxLatencyWriter_InitialHeaderTimerNonBlocking(t *testing.T) {
	dst := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:          dst,
		flush:        dst.Flush,
		latency:      50 * time.Millisecond,
		lastFlush:    time.Now().Add(-100 * time.Millisecond),
		flushPending: true,
		logger:       zap.NewNop(),
	}

	n, err := mlw.Write([]byte("burst payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 13 {
		t.Fatalf("expected 13 bytes written, got %d", n)
	}
	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected write after interval to flush immediately, got flush count %d", got)
	}
	if mlw.flushPending {
		t.Fatalf("expected flushPending to be false after immediate flush")
	}
}

func TestMaxLatencyWriter_RapidConsecutiveWrites(t *testing.T) {
	dst := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:       dst,
		flush:     dst.Flush,
		latency:   50 * time.Millisecond,
		lastFlush: time.Now(),
		logger:    zap.NewNop(),
	}
	defer mlw.stop()

	// Write rapid consecutive chunks
	for i := 0; i < 5; i++ {
		_, err := mlw.Write([]byte("chunk"))
		if err != nil {
			t.Fatalf("write error on chunk %d: %v", i, err)
		}
	}

	// Should not have flushed synchronously
	if got := dst.Flushes(); got != 0 {
		t.Fatalf("expected 0 flushes during rapid writes, got %d", got)
	}

	// Wait for background timer
	time.Sleep(100 * time.Millisecond)

	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected exactly 1 flush after interval, got %d", got)
	}
}

func TestMaxLatencyWriter_NegativeInterval(t *testing.T) {
	dst := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:       dst,
		flush:     dst.Flush,
		latency:   -1,
		lastFlush: time.Now(),
		logger:    zap.NewNop(),
	}

	_, _ = mlw.Write([]byte("first"))
	_, _ = mlw.Write([]byte("second"))

	if got := dst.Flushes(); got != 2 {
		t.Fatalf("expected 2 immediate flushes for negative latency, got %d", got)
	}
}

func BenchmarkMaxLatencyWriter_Write(b *testing.B) {
	dst := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:       dst,
		flush:     dst.Flush,
		latency:   10 * time.Millisecond,
		lastFlush: time.Now(),
		logger:    zap.NewNop(),
	}
	defer mlw.stop()

	p := []byte("benchmark payload data")
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = mlw.Write(p)
	}
}

