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

func TestMaxLatencyWriter_EarlyBodyWriteCancelsHeaderTimer(t *testing.T) {
	var dst bytes.Buffer
	var flushed sync.Map
	flushCount := 0
	var mu sync.Mutex

	flush := func() error {
		mu.Lock()
		flushCount++
		mu.Unlock()
		flushed.Store(flushCount, true)
		return nil
	}

	mlw := &maxLatencyWriter{
		dst:     &dst,
		flush:   flush,
		latency: 500 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// Perform a body write almost immediately before the 500ms header timer expires
	n, err := mlw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}

	mlw.mu.Lock()
	if mlw.headerTimer != nil {
		t.Errorf("expected headerTimer to be canceled and set to nil, got %v", mlw.headerTimer)
	}
	if !mlw.flushPending {
		t.Errorf("expected flushPending to be true for body write")
	}
	mlw.mu.Unlock()

	// Wait for body flush timer to execute
	time.Sleep(600 * time.Millisecond)

	mu.Lock()
	count := flushCount
	mu.Unlock()
	if count < 1 {
		t.Errorf("expected flush to be called for body write, got count %d", count)
	}
}

func TestMaxLatencyWriter_SlowBackendHeaderFlush(t *testing.T) {
	var dst bytes.Buffer
	flushed := make(chan struct{}, 1)

	flush := func() error {
		select {
		case flushed <- struct{}{}:
		default:
		}
		return nil
	}

	mlw := &maxLatencyWriter{
		dst:     &dst,
		flush:   flush,
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// Wait for the initial header flush timer to expire without writing body bytes
	select {
	case <-flushed:
		// Header flush succeeded on timer expiration
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for initial header flush")
	}

	mlw.mu.Lock()
	if mlw.headerTimer != nil {
		t.Errorf("expected headerTimer to be nil after firing, got %v", mlw.headerTimer)
	}
	mlw.mu.Unlock()
}

func TestMaxLatencyWriter_ConcurrentWriteAndHeaderTimer(t *testing.T) {
	var dst bytes.Buffer
	flush := func() error { return nil }

	mlw := &maxLatencyWriter{
		dst:     &dst,
		flush:   flush,
		latency: 1 * time.Millisecond,
		logger:  zap.NewNop(),
	}

	mlw.startHeaderTimer()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = mlw.Write([]byte("data"))
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}

	wg.Wait()
	mlw.stop()
}

func TestMaxLatencyWriter_Stop(t *testing.T) {
	var dst bytes.Buffer
	flush := func() error { return nil }

	mlw := &maxLatencyWriter{
		dst:     &dst,
		flush:   flush,
		latency: 500 * time.Millisecond,
		logger:  zap.NewNop(),
	}

	mlw.startHeaderTimer()
	mlw.stop()

	mlw.mu.Lock()
	defer mlw.mu.Unlock()

	if mlw.headerTimer != nil {
		t.Errorf("expected headerTimer to be nil after stop()")
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to be false after stop()")
	}
}
