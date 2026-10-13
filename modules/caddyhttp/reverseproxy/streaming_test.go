package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	bytes.Buffer
	mu          sync.Mutex
	flushCalls  int
	flushNotify chan struct{}
}

func (m *mockFlushWriter) Flush() error {
	m.mu.Lock()
	m.flushCalls++
	m.mu.Unlock()
	if m.flushNotify != nil {
		select {
		case m.flushNotify <- struct{}{}:
		default:
		}
	}
	return nil
}

func (m *mockFlushWriter) getFlushCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCalls
}

func TestMaxLatencyWriterHeaderFlush(t *testing.T) {
	mw := &mockFlushWriter{flushNotify: make(chan struct{}, 1)}
	mlw := &maxLatencyWriter{
		dst:     mw,
		flush:   mw.Flush,
		latency: 50 * time.Millisecond,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer(50 * time.Millisecond)

	// Check that flushPending is NOT true for payload writes
	mlw.mu.Lock()
	if mlw.flushPending {
		t.Error("expected flushPending to be false after startHeaderTimer")
	}
	mlw.mu.Unlock()

	// Wait for header timer flush
	select {
	case <-mw.flushNotify:
		if got := mw.getFlushCalls(); got != 1 {
			t.Errorf("expected 1 flush call, got %d", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for header flush")
	}
}

func TestMaxLatencyWriterFirstWriteStopsHeaderTimer(t *testing.T) {
	mw := &mockFlushWriter{flushNotify: make(chan struct{}, 5)}
	mlw := &maxLatencyWriter{
		dst:     mw,
		flush:   mw.Flush,
		latency: 50 * time.Millisecond,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer(100 * time.Millisecond)

	// Perform write before initial header flush timer fires
	time.Sleep(10 * time.Millisecond)
	n, err := mlw.Write([]byte("chunk1"))
	if err != nil || n != 6 {
		t.Fatalf("unexpected write result: n=%d err=%v", n, err)
	}

	// Verify header timer was stopped and flushPending is set for payload write
	mlw.mu.Lock()
	if mlw.ht != nil {
		t.Error("expected header timer ht to be nil after Write")
	}
	if !mlw.flushPending {
		t.Error("expected flushPending to be true after Write")
	}
	mlw.mu.Unlock()

	// Wait for payload timer to flush
	select {
	case <-mw.flushNotify:
		if got := mw.getFlushCalls(); got != 1 {
			t.Errorf("expected 1 flush call, got %d", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for payload flush")
	}

	// After flush, flushPending should be false
	mlw.mu.Lock()
	if mlw.flushPending {
		t.Error("expected flushPending to be false after delayedFlush executed")
	}
	mlw.mu.Unlock()
}

func TestMaxLatencyWriterNegativeLatency(t *testing.T) {
	mw := &mockFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     mw,
		flush:   mw.Flush,
		latency: -1,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer(-1)

	n, err := mlw.Write([]byte("instant"))
	if err != nil || n != 7 {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}

	if got := mw.getFlushCalls(); got != 1 {
		t.Errorf("expected immediate flush, got %d calls", got)
	}
}

func TestMaxLatencyWriterBurstyPayloadWrites(t *testing.T) {
	mw := &mockFlushWriter{flushNotify: make(chan struct{}, 5)}
	mlw := &maxLatencyWriter{
		dst:     mw,
		flush:   mw.Flush,
		latency: 50 * time.Millisecond,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer(100 * time.Millisecond)

	// Write 3 chunks in quick succession
	_, _ = mlw.Write([]byte("chunk1"))
	_, _ = mlw.Write([]byte("chunk2"))
	_, _ = mlw.Write([]byte("chunk3"))

	// Should flush once after ~50ms
	select {
	case <-mw.flushNotify:
		if got := mw.getFlushCalls(); got != 1 {
			t.Errorf("expected 1 flush call after first burst, got %d", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for burst flush")
	}

	// Write another chunk after the first flush completed
	_, _ = mlw.Write([]byte("chunk4"))

	// Should flush a second time
	select {
	case <-mw.flushNotify:
		if got := mw.getFlushCalls(); got != 2 {
			t.Errorf("expected 2 total flush calls, got %d", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for second flush")
	}
}


