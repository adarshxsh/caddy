package reverseproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
	flushes int
	mu      sync.Mutex
}

func (f *flushRecorder) Flush() {
	f.mu.Lock()
	f.flushes++
	f.mu.Unlock()
	f.ResponseRecorder.Flush()
}

func (f *flushRecorder) getFlushes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

func TestCopyResponseNegativeFlushInterval(t *testing.T) {
	h := Handler{}
	recorder := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("chunk1"))
		pw.Write([]byte("chunk2"))
		pw.Close()
	}()

	err := h.copyResponse(recorder, pr, -1, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if got := recorder.Body.String(); got != "chunk1chunk2" {
		t.Fatalf("copied body = %q, want %q", got, "chunk1chunk2")
	}

	if flushes := recorder.getFlushes(); flushes < 2 {
		t.Errorf("expected at least 2 flushes for negative flushInterval, got %d", flushes)
	}
}

func TestMaxLatencyWriterNegativeInterval(t *testing.T) {
	recorder := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	mlw := &maxLatencyWriter{
		dst:     recorder,
		flush:   http.NewResponseController(recorder).Flush,
		latency: -1,
		logger:  caddy.Log(),
	}
	defer mlw.stop()

	if mlw.t != nil {
		t.Errorf("expected nil timer for negative flush interval, got %v", mlw.t)
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to be false for negative flush interval")
	}

	n, err := mlw.Write([]byte("test"))
	if err != nil {
		t.Fatalf("unexpected Write error: %v", err)
	}
	if n != 4 {
		t.Errorf("wrote %d bytes, want 4", n)
	}

	if mlw.t != nil {
		t.Errorf("expected nil timer after Write for negative flush interval, got %v", mlw.t)
	}
	if flushes := recorder.getFlushes(); flushes != 1 {
		t.Errorf("expected 1 flush on Write, got %d", flushes)
	}
}

