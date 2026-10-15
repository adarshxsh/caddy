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

func TestMaxLatencyWriterStopFlushesPending(t *testing.T) {
	var flushed bool
	mlw := &maxLatencyWriter{
		dst: bytes.NewBuffer(nil),
		flush: func() error {
			flushed = true
			return nil
		},
		latency: 10 * time.Minute,
		logger:  caddy.Log(),
	}

	mlw.flushPending = true
	mlw.stop()

	if !flushed {
		t.Error("expected stop() to flush pending data, but it did not")
	}
	if mlw.flushPending {
		t.Error("expected flushPending to be false after stop()")
	}
}

type flushCountingRecorder struct {
	*httptest.ResponseRecorder
	flushCount int
}

func (f *flushCountingRecorder) Flush() {
	f.flushCount++
	f.ResponseRecorder.Flush()
}

func TestCopyResponseWithFlushIntervalFlushesTrailingData(t *testing.T) {
	h := Handler{}
	rec := &flushCountingRecorder{ResponseRecorder: httptest.NewRecorder()}
	src := strings.NewReader("hello trailing world")

	// Use long flush interval so timer won't fire during test
	err := h.copyResponse(rec, src, 10*time.Minute, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse error: %v", err)
	}

	if rec.Body.String() != "hello trailing world" {
		t.Errorf("got %q, want %q", rec.Body.String(), "hello trailing world")
	}

	if rec.flushCount == 0 {
		t.Error("expected Flush() to be called upon copyResponse completion, but flushCount was 0")
	}
}
