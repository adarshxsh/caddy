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

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushCount int
}

func (f *flushRecorder) Flush() {
	f.flushCount++
	f.ResponseRecorder.Flush()
}

func TestMaxLatencyWriterStopFinalFlush(t *testing.T) {
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	flushed := 0
	mlw := &maxLatencyWriter{
		dst: rec,
		flush: func() error {
			flushed++
			rec.Flush()
			return nil
		},
		latency:      10 * time.Second, // long latency so timer won't fire automatically
		flushPending: true,
		logger:       caddy.Log(),
	}

	// Write some trailing response bytes
	_, err := mlw.Write([]byte("hello trailing bytes"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if flushed != 0 {
		t.Fatalf("expected 0 flushes before stop, got %d", flushed)
	}

	mlw.stop()

	if flushed != 1 {
		t.Fatalf("expected 1 final flush upon stop, got %d", flushed)
	}
	if mlw.flushPending {
		t.Fatalf("expected flushPending to be false after stop")
	}

	// Second call to stop should be a no-op (no duplicate flush)
	mlw.stop()
	if flushed != 1 {
		t.Fatalf("expected still 1 flush after second stop, got %d", flushed)
	}
}

func TestMaxLatencyWriterStopNoPending(t *testing.T) {
	flushed := 0
	mlw := &maxLatencyWriter{
		dst: bytes.NewBuffer(nil),
		flush: func() error {
			flushed++
			return nil
		},
		latency:      10 * time.Second,
		flushPending: false,
		logger:       caddy.Log(),
	}

	mlw.stop()
	if flushed != 0 {
		t.Fatalf("expected 0 flushes when stop called without pending flush, got %d", flushed)
	}
}

func TestHandlerCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{}
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	src := strings.NewReader("streaming response data")

	err := h.copyResponse(rec, src, 100*time.Millisecond, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if rec.Body.String() != "streaming response data" {
		t.Fatalf("got body %q, want %q", rec.Body.String(), "streaming response data")
	}
	if rec.flushCount < 1 {
		t.Fatalf("expected at least 1 flush upon stream completion, got %d", rec.flushCount)
	}
}
