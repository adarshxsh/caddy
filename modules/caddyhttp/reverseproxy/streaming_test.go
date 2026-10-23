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

func TestMaxLatencyWriterStopFlushes(t *testing.T) {
	var flushCount int
	var mu sync.Mutex

	dst := new(bytes.Buffer)
	mlw := &maxLatencyWriter{
		dst: dst,
		flush: func() error {
			mu.Lock()
			flushCount++
			mu.Unlock()
			return nil
		},
		latency: 10 * time.Minute, // ensure delayed flush timer won't trigger automatically
		logger:  zap.NewNop(),
	}

	n, err := mlw.Write([]byte("trailing response data"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len("trailing response data") {
		t.Fatalf("wrote %d bytes, expected %d", n, len("trailing response data"))
	}

	mu.Lock()
	if flushCount != 0 {
		t.Fatalf("flush count before stop = %d, want 0", flushCount)
	}
	mu.Unlock()

	// Stopping maxLatencyWriter must issue a final flush
	mlw.stop()

	mu.Lock()
	if flushCount != 1 {
		t.Fatalf("flush count after stop = %d, want 1", flushCount)
	}
	mu.Unlock()
}

func TestHandlerCopyResponseFlushInterval(t *testing.T) {
	h := Handler{}
	recorder := httptest.NewRecorder()
	src := strings.NewReader("hello world trailing payload")

	err := h.copyResponse(recorder, src, 100*time.Millisecond, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if got := recorder.Body.String(); got != "hello world trailing payload" {
		t.Fatalf("got body %q, want %q", got, "hello world trailing payload")
	}
	if !recorder.Flushed {
		t.Fatalf("expected recorder to be flushed upon copyResponse completion")
	}
}
