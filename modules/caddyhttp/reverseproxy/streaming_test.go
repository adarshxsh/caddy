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

func TestH2ReadWriteCloserImmediateFlush(t *testing.T) {
	var dst bytes.Buffer
	var flushCount int
	mlw := &maxLatencyWriter{
		dst: &dst,
		flush: func() error {
			flushCount++
			return nil
		},
		latency: -1,
		logger:  caddy.Log(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser:       io.NopCloser(strings.NewReader("")),
		maxLatencyWriter: mlw,
	}

	for i := 0; i < 5; i++ {
		_, err := rwc.Write([]byte("chunk"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	if flushCount != 5 {
		t.Fatalf("expected 5 immediate flushes, got %d", flushCount)
	}

	if err := rwc.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Close shouldn't trigger an extra flush when latency < 0
	if flushCount != 5 {
		t.Fatalf("expected flush count to remain 5 after close, got %d", flushCount)
	}
}

func TestH2ReadWriteCloserMaxLatencyFlush(t *testing.T) {
	var dst bytes.Buffer
	var mu sync.Mutex
	var flushCount int
	mlw := &maxLatencyWriter{
		dst: &dst,
		flush: func() error {
			mu.Lock()
			flushCount++
			mu.Unlock()
			return nil
		},
		latency: 500 * time.Millisecond,
		logger:  caddy.Log(),
	}
	rwc := h2ReadWriteCloser{
		ReadCloser:       io.NopCloser(strings.NewReader("")),
		maxLatencyWriter: mlw,
	}

	// Rapid consecutive writes should not flush immediately
	for i := 0; i < 3; i++ {
		_, err := rwc.Write([]byte("data"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	mu.Lock()
	if flushCount != 0 {
		mu.Unlock()
		t.Fatalf("expected 0 flushes immediately after rapid writes, got %d", flushCount)
	}
	mu.Unlock()

	// Closing stream should flush pending writes
	if err := rwc.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	mu.Lock()
	if flushCount != 1 {
		mu.Unlock()
		t.Fatalf("expected 1 flush on close, got %d", flushCount)
	}
	mu.Unlock()

	if got := dst.String(); got != "datadatadata" {
		t.Fatalf("expected buffer 'datadatadata', got %q", got)
	}
}

func TestH2ReadWriteCloserDefaultFlushInterval(t *testing.T) {
	h := Handler{
		FlushInterval: 0,
	}
	if got := time.Duration(h.FlushInterval); got != 0 {
		t.Fatalf("expected Handler FlushInterval 0, got %v", got)
	}
	// defaultFlushInterval constant should be 250ms
	if defaultFlushInterval != 250*time.Millisecond {
		t.Fatalf("expected defaultFlushInterval to be 250ms, got %v", defaultFlushInterval)
	}
}
