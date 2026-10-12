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
	"go.uber.org/zap"
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

type testFlushWriter struct {
	bytes.Buffer
	flushCount int
	mu         sync.Mutex
}

func (w *testFlushWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushCount++
	return nil
}

func (w *testFlushWriter) getFlushCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushCount
}

func TestMaxLatencyWriterInitialHeaderFlush(t *testing.T) {
	var tw testFlushWriter
	mlw := &maxLatencyWriter{
		dst:     &tw,
		flush:   tw.Flush,
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// Wait long enough for the initial header flush timer to fire
	time.Sleep(100 * time.Millisecond)

	if got := tw.getFlushCount(); got != 1 {
		t.Errorf("expected 1 initial header flush, got %d", got)
	}
}

func TestMaxLatencyWriterFirstWriteCancelsHeaderTimer(t *testing.T) {
	var tw testFlushWriter
	mlw := &maxLatencyWriter{
		dst:     &tw,
		flush:   tw.Flush,
		latency: 100 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// Write payload after 10ms (well before the 100ms header timer)
	time.Sleep(10 * time.Millisecond)
	n, err := mlw.Write([]byte("chunk1"))
	if err != nil || n != 6 {
		t.Fatalf("Write error = %v, n = %d", err, n)
	}

	// At 50ms from start (40ms after Write), header timer should have been canceled,
	// and payload timer (100ms duration) has not fired yet.
	time.Sleep(40 * time.Millisecond)
	if got := tw.getFlushCount(); got != 0 {
		t.Errorf("expected 0 flushes at 50ms, got %d", got)
	}

	// Wait until payload flush timer fires (total ~150ms from start)
	time.Sleep(80 * time.Millisecond)
	if got := tw.getFlushCount(); got != 1 {
		t.Errorf("expected 1 payload flush at 130ms+, got %d", got)
	}
}

func TestMaxLatencyWriterImmediateFlush(t *testing.T) {
	var tw testFlushWriter
	mlw := &maxLatencyWriter{
		dst:     &tw,
		flush:   tw.Flush,
		latency: -1,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.Write([]byte("fast"))
	if got := tw.getFlushCount(); got != 1 {
		t.Errorf("expected 1 immediate flush, got %d", got)
	}
}

func TestMaxLatencyWriterConcurrency(t *testing.T) {
	var tw testFlushWriter
	mlw := &maxLatencyWriter{
		dst:     &tw,
		flush:   tw.Flush,
		latency: 5 * time.Millisecond,
		logger:  zap.NewNop(),
	}

	mlw.startHeaderTimer()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				mlw.Write([]byte("data"))
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		mlw.stop()
	}()

	wg.Wait()
}
