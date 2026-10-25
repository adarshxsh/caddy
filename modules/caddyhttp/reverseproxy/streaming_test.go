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
	mu         sync.Mutex
	flushCount int
}

func (m *mockFlushWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCount++
	return nil
}

func (m *mockFlushWriter) getFlushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCount
}

func TestMaxLatencyWriter_EagerFirstWriteAndFollowOn(t *testing.T) {
	dst := &mockFlushWriter{}
	latency := 100 * time.Millisecond

	mlw := &maxLatencyWriter{
		dst:        dst,
		flush:      dst.Flush,
		latency:    latency,
		logger:     caddy.Log(),
		firstWrite: true,
	}
	defer mlw.stop()

	// Initial header flush timer setup as in copyResponse
	mlw.flushPending = true
	mlw.seq++
	seq := mlw.seq
	mlw.t = time.AfterFunc(latency, func() { mlw.delayedFlush(seq) })

	if got := dst.getFlushCount(); got != 0 {
		t.Fatalf("expected initial flushCount=0, got %d", got)
	}

	// First write should immediately flush and cancel header timer
	_, err := mlw.Write([]byte("first"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if got := dst.getFlushCount(); got != 1 {
		t.Fatalf("expected immediate flushCount=1 after first write, got %d", got)
	}

	// Follow-on write within flush window should be buffered
	_, err = mlw.Write([]byte("second"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if got := dst.getFlushCount(); got != 1 {
		t.Fatalf("expected flushCount=1 during follow-on write window, got %d", got)
	}

	// Wait for deferred timer to fire
	time.Sleep(150 * time.Millisecond)
	if got := dst.getFlushCount(); got != 2 {
		t.Fatalf("expected flushCount=2 after deferred timer expiration, got %d", got)
	}

	// Next write after timer expiration (idle period) should eagerly flush immediately
	_, err = mlw.Write([]byte("third"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if got := dst.getFlushCount(); got != 3 {
		t.Fatalf("expected immediate flushCount=3 after idle period write, got %d", got)
	}
}

func TestMaxLatencyWriter_HeaderTimerFiresWhenNoWrite(t *testing.T) {
	dst := &mockFlushWriter{}
	latency := 50 * time.Millisecond

	mlw := &maxLatencyWriter{
		dst:        dst,
		flush:      dst.Flush,
		latency:    latency,
		logger:     caddy.Log(),
		firstWrite: true,
	}
	defer mlw.stop()

	mlw.flushPending = true
	mlw.seq++
	seq := mlw.seq
	mlw.t = time.AfterFunc(latency, func() { mlw.delayedFlush(seq) })

	// Wait for header timer to fire
	time.Sleep(100 * time.Millisecond)
	if got := dst.getFlushCount(); got != 1 {
		t.Fatalf("expected header flush count=1, got %d", got)
	}

	// First write after header timer fired
	_, err := mlw.Write([]byte("body"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if got := dst.getFlushCount(); got != 2 {
		t.Fatalf("expected body write to trigger immediate flushCount=2, got %d", got)
	}
}

func TestMaxLatencyWriter_ConcurrentWritesAndStop(t *testing.T) {
	dst := &mockFlushWriter{}
	latency := 10 * time.Millisecond

	mlw := &maxLatencyWriter{
		dst:        dst,
		flush:      dst.Flush,
		latency:    latency,
		logger:     caddy.Log(),
		firstWrite: true,
	}

	mlw.flushPending = true
	mlw.seq++
	seq := mlw.seq
	mlw.t = time.AfterFunc(latency, func() { mlw.delayedFlush(seq) })

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = mlw.Write([]byte("data"))
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	mlw.stop()
}
