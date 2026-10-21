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

func TestMaxLatencyWriterStopFlushes(t *testing.T) {
	var flushCount int
	dst := &bytes.Buffer{}
	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			flushCount++
			return nil
		},
		latency: 1 * time.Hour,
		logger:  zap.NewNop(),
	}

	n, err := mlw.Write([]byte("hello trailing bytes"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if n != 20 {
		t.Fatalf("expected 20 bytes written, got %d", n)
	}

	if flushCount != 0 {
		t.Fatalf("expected 0 flushes before stop, got %d", flushCount)
	}

	mlw.stop()

	if flushCount != 1 {
		t.Fatalf("expected 1 flush after stop, got %d", flushCount)
	}
}

func TestHandlerCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{}
	src := strings.NewReader("response body payload")

	flushed := false
	recorder := httptest.NewRecorder()
	fw := &flushTrackingResponseWriter{
		ResponseRecorder: recorder,
		onFlush: func() {
			flushed = true
		},
	}

	err := h.copyResponse(fw, src, 10*time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if recorder.Body.String() != "response body payload" {
		t.Fatalf("unexpected body: %q", recorder.Body.String())
	}

	if !flushed {
		t.Fatalf("expected flush to be called on stop when response copy finishes")
	}
}

type flushTrackingResponseWriter struct {
	*httptest.ResponseRecorder
	onFlush func()
}

func (w *flushTrackingResponseWriter) Flush() {
	if w.onFlush != nil {
		w.onFlush()
	}
	w.ResponseRecorder.Flush()
}

