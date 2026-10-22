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

type flushTracker struct {
	http.ResponseWriter
	mu         sync.Mutex
	flushCount int
	body       bytes.Buffer
}

func (f *flushTracker) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushCount++
}

func (f *flushTracker) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body.Write(p)
}

func (f *flushTracker) getFlushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushCount
}

func (f *flushTracker) getBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body.String()
}

func TestMaxLatencyWriterInitialization(t *testing.T) {
	rec := httptest.NewRecorder()
	ft := &flushTracker{ResponseWriter: rec}

	src, pw := io.Pipe()
	defer pw.Close()

	var copyErr error
	done := make(chan struct{})
	h := Handler{}

	go func() {
		copyErr = h.copyResponse(ft, src, 50*time.Millisecond, caddy.Log())
		close(done)
	}()

	// Give a short window for copyResponse to initialize maxLatencyWriter and flush headers
	time.Sleep(10 * time.Millisecond)

	// Verify that flushCount is 1 (explicit header flush on init)
	if count := ft.getFlushCount(); count != 1 {
		t.Fatalf("expected 1 header flush on initialization, got %d", count)
	}

	// Write first payload chunk
	pw.Write([]byte("chunk1"))

	// Immediately check before flushInterval (50ms) elapses
	time.Sleep(10 * time.Millisecond)
	// Flush count should still be 1 because timer is pending
	if count := ft.getFlushCount(); count != 1 {
		t.Fatalf("expected flush count to still be 1 before timer elapses, got %d", count)
	}

	// Write second payload chunk while flush is pending
	pw.Write([]byte("chunk2"))

	// Wait for timer to fire
	time.Sleep(60 * time.Millisecond)
	// Flush count should now be 2 (header flush + 1 delayed flush for chunk1 and chunk2)
	if count := ft.getFlushCount(); count != 2 {
		t.Fatalf("expected flush count to be 2 after timer fires, got %d", count)
	}

	if body := ft.getBody(); body != "chunk1chunk2" {
		t.Fatalf("expected body 'chunk1chunk2', got %q", body)
	}

	pw.Close()
	<-done
	if copyErr != nil {
		t.Fatalf("copyResponse returned error: %v", copyErr)
	}
}

func TestMaxLatencyWriterDirect(t *testing.T) {
	rec := httptest.NewRecorder()
	ft := &flushTracker{ResponseWriter: rec}

	mlw := &maxLatencyWriter{
		dst:     ft,
		flush:   http.NewResponseController(ft).Flush,
		latency: 30 * time.Millisecond,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	// Initial state: flushPending is false, t is nil
	if mlw.flushPending {
		t.Fatal("expected flushPending to be false initially")
	}
	if mlw.t != nil {
		t.Fatal("expected timer t to be nil initially")
	}

	// Flush headers explicitly as copyResponse does
	_ = mlw.flush()
	if count := ft.getFlushCount(); count != 1 {
		t.Fatalf("expected flush count 1, got %d", count)
	}
	if mlw.flushPending {
		t.Fatal("expected flushPending to remain false after header flush")
	}

	// First Write arms timer
	n, err := mlw.Write([]byte("frame1"))
	if err != nil || n != 6 {
		t.Fatalf("Write failed: %v, %d", err, n)
	}

	mlw.mu.Lock()
	pending := mlw.flushPending
	timerSet := mlw.t != nil
	mlw.mu.Unlock()

	if !pending {
		t.Fatal("expected flushPending to be true after first Write")
	}
	if !timerSet {
		t.Fatal("expected timer t to be set after first Write")
	}

	// Second Write while flush is pending
	n, err = mlw.Write([]byte("frame2"))
	if err != nil || n != 6 {
		t.Fatalf("Write failed: %v, %d", err, n)
	}

	// Wait for timer to expire
	time.Sleep(50 * time.Millisecond)

	mlw.mu.Lock()
	pending = mlw.flushPending
	mlw.mu.Unlock()

	if pending {
		t.Fatal("expected flushPending to reset to false after delayedFlush fires")
	}
	if count := ft.getFlushCount(); count != 2 {
		t.Fatalf("expected flush count 2, got %d", count)
	}

	// Third Write after flush has reset flushPending
	n, err = mlw.Write([]byte("frame3"))
	if err != nil || n != 6 {
		t.Fatalf("Write failed: %v, %d", err, n)
	}

	mlw.mu.Lock()
	pending = mlw.flushPending
	mlw.mu.Unlock()

	if !pending {
		t.Fatal("expected flushPending to be re-armed to true on frame3 Write")
	}

	time.Sleep(50 * time.Millisecond)

	if count := ft.getFlushCount(); count != 3 {
		t.Fatalf("expected flush count 3, got %d", count)
	}
	if body := ft.getBody(); body != "frame1frame2frame3" {
		t.Fatalf("expected full body 'frame1frame2frame3', got %q", body)
	}
}

func TestMaxLatencyWriterNegativeInterval(t *testing.T) {
	rec := httptest.NewRecorder()
	ft := &flushTracker{ResponseWriter: rec}

	mlw := &maxLatencyWriter{
		dst:     ft,
		flush:   http.NewResponseController(ft).Flush,
		latency: -1,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	_ = mlw.flush()
	if count := ft.getFlushCount(); count != 1 {
		t.Fatalf("expected flush count 1 after init header flush, got %d", count)
	}

	_, err := mlw.Write([]byte("a"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if count := ft.getFlushCount(); count != 2 {
		t.Fatalf("expected flush count 2 after immediate flush write, got %d", count)
	}
	if mlw.flushPending {
		t.Fatal("expected flushPending to be false for negative latency")
	}
}
