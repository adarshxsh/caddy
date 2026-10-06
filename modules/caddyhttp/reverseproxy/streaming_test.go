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

func TestHandlerCopyResponseNegativeFlushInterval(t *testing.T) {
	h := Handler{}
	testdata := []string{
		"",
		"hello world",
		strings.Repeat("a", defaultBufferSize),
	}

	for _, flushInterval := range []time.Duration{-1, -100 * time.Millisecond} {
		for _, d := range testdata {
			dst := bytes.NewBuffer(nil)
			recorder := httptest.NewRecorder()
			recorder.Body = dst

			src := bytes.NewBuffer([]byte(d))
			err := h.copyResponse(recorder, src, flushInterval, caddy.Log())
			if err != nil {
				t.Fatalf("copyResponse failed with error: %v", err)
			}
			out := dst.String()
			if out != d {
				t.Errorf("bad read: got %q, want %q", out, d)
			}
			if len(d) > 0 && !recorder.Flushed {
				t.Errorf("expected recorder to be flushed for negative flush interval %v", flushInterval)
			}
		}
	}
}

func TestMaxLatencyWriterNegativeLatency(t *testing.T) {
	flushed := false
	dst := bytes.NewBuffer(nil)
	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			flushed = true
			return nil
		},
		latency: -1,
		logger:  zap.NewNop(),
	}

	if mlw.t != nil {
		t.Errorf("expected timer to be nil before write")
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to be false before write")
	}

	n, err := mlw.Write([]byte("test data"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 9 {
		t.Errorf("wrote %d bytes, want 9", n)
	}

	if !flushed {
		t.Errorf("expected immediate flush on write")
	}
	if mlw.t != nil {
		t.Errorf("expected timer to remain nil after write for negative latency")
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to remain false after write for negative latency")
	}
}

