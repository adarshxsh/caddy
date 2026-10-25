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

func TestMaxLatencyWriterStopFinalFlush(t *testing.T) {
	var flushCount int
	mlw := &maxLatencyWriter{
		flush: func() error {
			flushCount++
			return nil
		},
		latency:      time.Hour,
		flushPending: true,
		logger:       zap.NewNop(),
	}

	mlw.stop()

	if flushCount != 1 {
		t.Fatalf("expected flushCount to be 1 after stop, got %d", flushCount)
	}
	if mlw.flushPending {
		t.Fatalf("expected flushPending to be false after stop, got %v", mlw.flushPending)
	}

	// Calling stop again should not trigger another flush
	mlw.stop()
	if flushCount != 1 {
		t.Fatalf("expected flushCount to remain 1 on second stop, got %d", flushCount)
	}
}

type flushTrackingResponseWriter struct {
	*httptest.ResponseRecorder
	flushCount int
}

func (f *flushTrackingResponseWriter) Flush() {
	f.flushCount++
	f.ResponseRecorder.Flush()
}

func TestCopyResponseFinalFlushOnExit(t *testing.T) {
	h := Handler{}
	rec := &flushTrackingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
	}
	data := "trailing data"
	src := strings.NewReader(data)

	// Use a long flush interval so the background timer won't fire
	err := h.copyResponse(rec, src, 10*time.Minute, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse error: %v", err)
	}

	if rec.Body.String() != data {
		t.Fatalf("got body %q, want %q", rec.Body.String(), data)
	}
	if rec.flushCount == 0 {
		t.Fatalf("expected at least 1 flush call on copyResponse exit, got %d", rec.flushCount)
	}
}
