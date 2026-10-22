package reverseproxy

import (
	"bytes"
	"errors"
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

func TestMaxLatencyWriterStopFlushesWhenPending(t *testing.T) {
	flushed := false
	mlw := &maxLatencyWriter{
		flush: func() error {
			flushed = true
			return nil
		},
		flushPending: true,
		logger:       zap.NewNop(),
	}

	mlw.stop()

	if !flushed {
		t.Errorf("expected flush() to be called on stop() when flushPending is true")
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to be false after stop()")
	}
}

func TestMaxLatencyWriterStopNoFlushWhenNotPending(t *testing.T) {
	flushed := false
	mlw := &maxLatencyWriter{
		flush: func() error {
			flushed = true
			return nil
		},
		flushPending: false,
		logger:       zap.NewNop(),
	}

	mlw.stop()

	if flushed {
		t.Errorf("expected flush() NOT to be called on stop() when flushPending is false")
	}
}

func TestMaxLatencyWriterStopHandlesFlushError(t *testing.T) {
	mlw := &maxLatencyWriter{
		flush: func() error {
			return errors.New("flush failed")
		},
		flushPending: true,
		logger:       zap.NewNop(),
	}

	// Must not panic or fail cleanup
	mlw.stop()

	if mlw.flushPending {
		t.Errorf("expected flushPending to be false after stop() even if flush returns an error")
	}
}

func TestHandlerCopyResponseWithFlushIntervalFlushesTrailingBytes(t *testing.T) {
	h := Handler{}
	recorder := httptest.NewRecorder()
	src := strings.NewReader("hello world streaming")

	err := h.copyResponse(recorder, src, 100*time.Millisecond, zap.NewNop())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if !recorder.Flushed {
		t.Errorf("expected recorder to be flushed upon stream completion")
	}
	if recorder.Body.String() != "hello world streaming" {
		t.Errorf("got %q, want %q", recorder.Body.String(), "hello world streaming")
	}
}

