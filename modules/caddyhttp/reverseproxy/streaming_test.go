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

type dummyFlushWriter struct {
	bytes.Buffer
	mu         sync.Mutex
	flushCount int
}

func (d *dummyFlushWriter) Flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.flushCount++
	return nil
}

func (d *dummyFlushWriter) Flushes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushCount
}

func TestMaxLatencyWriterFirstWriteFlush(t *testing.T) {
	dst := &dummyFlushWriter{}
	latency := 100 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:                dst,
		flush:              dst.Flush,
		latency:            latency,
		logger:             zap.NewNop(),
		initialHeaderFlush: true,
	}
	defer mlw.stop()

	mlw.flushPending = true
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)

	// First write should flush immediately and cancel the initial timer
	_, err := mlw.Write([]byte("chunk1"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected 1 flush immediately on first write, got %d", got)
	}

	// Second write should be batched via timer
	_, err = mlw.Write([]byte("chunk2"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected flush count to remain 1 before timer expires, got %d", got)
	}

	time.Sleep(150 * time.Millisecond)

	if got := dst.Flushes(); got != 2 {
		t.Fatalf("expected 2 flushes after timer expires, got %d", got)
	}
}

func TestMaxLatencyWriterDelayedFlushNoWrite(t *testing.T) {
	dst := &dummyFlushWriter{}
	latency := 50 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:                dst,
		flush:              dst.Flush,
		latency:            latency,
		logger:             zap.NewNop(),
		initialHeaderFlush: true,
	}
	defer mlw.stop()

	mlw.flushPending = true
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)

	// Wait for initial timer to expire without any Write call
	time.Sleep(100 * time.Millisecond)

	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected 1 delayed flush for headers when no write occurred, got %d", got)
	}

	// Body write occurring after initial delayed flush
	_, err := mlw.Write([]byte("late body"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected flush count to remain 1 before second timer expires, got %d", got)
	}

	time.Sleep(100 * time.Millisecond)

	if got := dst.Flushes(); got != 2 {
		t.Fatalf("expected 2 flushes after body timer expires, got %d", got)
	}
}

func TestMaxLatencyWriterNegativeLatency(t *testing.T) {
	dst := &dummyFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     dst,
		flush:   dst.Flush,
		latency: -1,
		logger:  zap.NewNop(),
	}

	_, err := mlw.Write([]byte("a"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := dst.Flushes(); got != 1 {
		t.Fatalf("expected 1 flush for negative latency, got %d", got)
	}

	_, err = mlw.Write([]byte("b"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := dst.Flushes(); got != 2 {
		t.Fatalf("expected 2 flushes for negative latency, got %d", got)
	}
}
