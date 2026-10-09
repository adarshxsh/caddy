package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

type testFlushRecorder struct {
	*httptest.ResponseRecorder
	flushCount atomic.Int32
}

func (r *testFlushRecorder) Flush() {
	r.flushCount.Add(1)
	r.ResponseRecorder.Flush()
}

func TestHandlerCopyResponseNegativeFlushInterval(t *testing.T) {
	h := Handler{}

	pr, pw := io.Pipe()
	recorder := &testFlushRecorder{ResponseRecorder: httptest.NewRecorder()}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.copyResponse(recorder, pr, -1, caddy.Log())
	}()

	// Ensure no background timer triggers a flush when flushInterval is negative
	time.Sleep(50 * time.Millisecond)
	if count := recorder.flushCount.Load(); count != 0 {
		t.Fatalf("expected 0 flushes before writes for negative flushInterval, got %d", count)
	}

	// Write first chunk and verify immediate inline flush
	_, err := pw.Write([]byte("chunk1"))
	if err != nil {
		t.Fatalf("failed to write chunk1: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if count := recorder.flushCount.Load(); count != 1 {
		t.Fatalf("expected 1 flush after chunk1 write, got %d", count)
	}

	// Write second chunk and verify immediate inline flush
	_, err = pw.Write([]byte("chunk2"))
	if err != nil {
		t.Fatalf("failed to write chunk2: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if count := recorder.flushCount.Load(); count != 2 {
		t.Fatalf("expected 2 flushes after chunk2 write, got %d", count)
	}

	pw.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("copyResponse returned error: %v", err)
	}

	if got := recorder.Body.String(); got != "chunk1chunk2" {
		t.Fatalf("expected body %q, got %q", "chunk1chunk2", got)
	}
}
