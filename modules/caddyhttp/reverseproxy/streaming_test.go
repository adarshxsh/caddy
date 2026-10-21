package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestMaxLatencyWriterInitialHeaderTimerResetOnWrite(t *testing.T) {
	var flushCount atomic.Int32
	dst := bytes.NewBuffer(nil)

	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			flushCount.Add(1)
			return nil
		},
		latency: 60 * time.Millisecond,
		logger:  zap.NewNop(),
	}

	// Simulate copyResponse setting up initial header flush timer
	mlw.flushPending = true
	mlw.t = time.AfterFunc(mlw.latency, mlw.delayedFlush)
	defer mlw.stop()

	// Write body data after 10ms (before initial timer expires)
	time.Sleep(10 * time.Millisecond)
	_, err := mlw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	// At t ~35ms, initial timer was reset to fire at t ~70ms, so no flush yet.
	time.Sleep(25 * time.Millisecond)
	if got := flushCount.Load(); got != 0 {
		t.Fatalf("expected 0 flushes at t=35ms, got %d", got)
	}

	// Wait until t ~85ms (after reset timer fires at ~70ms)
	time.Sleep(50 * time.Millisecond)
	if got := flushCount.Load(); got != 1 {
		t.Fatalf("expected 1 flush at t=85ms, got %d", got)
	}
}

func TestMaxLatencyWriterBurstyWrites(t *testing.T) {
	var flushCount atomic.Int32
	dst := bytes.NewBuffer(nil)

	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			flushCount.Add(1)
			return nil
		},
		latency: 50 * time.Millisecond,
		logger:  zap.NewNop(),
	}
	defer mlw.stop()

	// Write three bursty chunks spaced 20ms apart
	for i := 0; i < 3; i++ {
		_, err := mlw.Write([]byte("chunk"))
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// At t=40ms (last write was at t=40ms, so reset timer fires at ~90ms),
	// flush count should still be 0.
	if got := flushCount.Load(); got != 0 {
		t.Fatalf("expected 0 flushes during burst, got %d", got)
	}

	// Wait for reset timer to fire (50ms after last write)
	time.Sleep(60 * time.Millisecond)
	if got := flushCount.Load(); got != 1 {
		t.Fatalf("expected 1 flush after burst completed, got %d", got)
	}
}

func TestMaxLatencyWriterImmediateFlush(t *testing.T) {
	var flushCount atomic.Int32
	dst := bytes.NewBuffer(nil)

	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			flushCount.Add(1)
			return nil
		},
		latency: -1,
		logger:  zap.NewNop(),
	}

	_, err := mlw.Write([]byte("data"))
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	if got := flushCount.Load(); got != 1 {
		t.Fatalf("expected immediate flush count = 1, got %d", got)
	}
}
