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

type testFlushWriter struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	flushCount int
}

func (w *testFlushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *testFlushWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushCount++
	return nil
}

func (w *testFlushWriter) Flushes() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushCount
}

func (w *testFlushWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestMaxLatencyWriterFirstWriteFlushesImmediately(t *testing.T) {
	tfw := &testFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     tfw,
		flush:   tfw.Flush,
		latency: 100 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	if got := tfw.Flushes(); got != 0 {
		t.Fatalf("expected 0 flushes initially, got %d", got)
	}

	n, err := mlw.Write([]byte("first chunk"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 11 {
		t.Fatalf("expected 11 bytes written, got %d", n)
	}

	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected immediate flush on first body write, got %d flushes", got)
	}

	time.Sleep(150 * time.Millisecond)
	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected timer to be canceled and flush count to remain 1, got %d", got)
	}
}

func TestMaxLatencyWriterIntervalFlushing(t *testing.T) {
	tfw := &testFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     tfw,
		flush:   tfw.Flush,
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// 1st write flushes immediately (cancels initial header timer)
	_, _ = mlw.Write([]byte("chunk1"))
	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected 1 flush after 1st write, got %d", got)
	}

	// 2nd write schedules interval flush timer
	_, _ = mlw.Write([]byte("chunk2"))
	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected 1 flush immediately after 2nd write, got %d", got)
	}

	// 3rd write buffers under pending interval flush
	_, _ = mlw.Write([]byte("chunk3"))
	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected 1 flush before timer fires, got %d", got)
	}

	time.Sleep(100 * time.Millisecond)
	if got := tfw.Flushes(); got != 2 {
		t.Fatalf("expected interval flush to occur, got %d flushes", got)
	}

	if got := tfw.String(); got != "chunk1chunk2chunk3" {
		t.Fatalf("expected full content, got %q", got)
	}
}

func TestMaxLatencyWriterHeaderTimerFiresOnDelay(t *testing.T) {
	tfw := &testFlushWriter{}
	mlw := &maxLatencyWriter{
		dst:     tfw,
		flush:   tfw.Flush,
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	if got := tfw.Flushes(); got != 0 {
		t.Fatalf("expected 0 flushes initially, got %d", got)
	}

	time.Sleep(100 * time.Millisecond)
	if got := tfw.Flushes(); got != 1 {
		t.Fatalf("expected header timer to fire automatically after delay, got %d flushes", got)
	}
}
