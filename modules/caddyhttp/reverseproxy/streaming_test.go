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

func TestMaxLatencyWriterStopFlushesPending(t *testing.T) {
	var flushed int
	mlw := &maxLatencyWriter{
		dst: io.Discard,
		flush: func() error {
			flushed++
			return nil
		},
		latency:      time.Hour,
		flushPending: true,
		logger:       zap.NewNop(),
	}

	mlw.stop()
	if flushed != 1 {
		t.Errorf("expected 1 flush on stop when flushPending is true, got %d", flushed)
	}

	// Stopping again should not flush a second time
	mlw.stop()
	if flushed != 1 {
		t.Errorf("expected no additional flush on second stop, got %d", flushed)
	}
}

func TestHandlerCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{}
	recorder := httptest.NewRecorder()
	src := strings.NewReader("hello trailing bytes")

	err := h.copyResponse(recorder, src, 10*time.Minute, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if !recorder.Flushed {
		t.Errorf("expected recorder to be flushed upon completion of copyResponse")
	}
	if got := recorder.Body.String(); got != "hello trailing bytes" {
		t.Errorf("expected body %q, got %q", "hello trailing bytes", got)
	}
}
