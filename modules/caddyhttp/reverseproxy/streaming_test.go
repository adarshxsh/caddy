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

func TestMaxLatencyWriterStopFlushes(t *testing.T) {
	var flushCount int
	var dst bytes.Buffer

	mlw := &maxLatencyWriter{
		dst: &dst,
		flush: func() error {
			flushCount++
			return nil
		},
		latency: 1 * time.Hour,
		logger:  caddy.Log(),
	}

	n, err := mlw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write error: %v, n=%d", err, n)
	}

	if !mlw.flushPending {
		t.Fatalf("expected flushPending to be true")
	}
	if flushCount != 0 {
		t.Fatalf("expected flushCount to be 0 before stop, got %d", flushCount)
	}

	mlw.stop()

	if mlw.flushPending {
		t.Fatalf("expected flushPending to be false after stop")
	}
	if flushCount != 1 {
		t.Fatalf("expected flushCount to be 1 after stop, got %d", flushCount)
	}

	// Calling stop again should not trigger another flush
	mlw.stop()
	if flushCount != 1 {
		t.Fatalf("expected flushCount to remain 1 on second stop, got %d", flushCount)
	}
}

func TestCopyResponseFlushesOnStreamCompletion(t *testing.T) {
	h := Handler{}

	t.Run("flushInterval = 0", func(t *testing.T) {
		dst := bytes.NewBuffer(nil)
		recorder := httptest.NewRecorder()
		recorder.Body = dst

		src := strings.NewReader("stream data")
		err := h.copyResponse(recorder, src, 0, caddy.Log())
		if err != nil {
			t.Fatalf("copyResponse failed: %v", err)
		}
		if !recorder.Flushed {
			t.Errorf("expected recorder to be flushed when flushInterval = 0")
		}
		if dst.String() != "stream data" {
			t.Errorf("got %q, want 'stream data'", dst.String())
		}
	})

	t.Run("flushInterval > 0", func(t *testing.T) {
		dst := bytes.NewBuffer(nil)
		recorder := httptest.NewRecorder()
		recorder.Body = dst

		src := strings.NewReader("stream data with latency")
		err := h.copyResponse(recorder, src, 100*time.Second, caddy.Log())
		if err != nil {
			t.Fatalf("copyResponse failed: %v", err)
		}
		if !recorder.Flushed {
			t.Errorf("expected recorder to be flushed when flushInterval > 0")
		}
		if dst.String() != "stream data with latency" {
			t.Errorf("got %q, want 'stream data with latency'", dst.String())
		}
	})
}

type errReader struct {
	err error
}

func (e errReader) Read(p []byte) (int, error) {
	return 0, e.err
}

func TestCopyResponsePreservesReadError(t *testing.T) {
	h := Handler{}
	recorder := httptest.NewRecorder()
	expectedErr := bytes.ErrTooLarge // arbitrary sentinel error

	err := h.copyResponse(recorder, errReader{err: expectedErr}, 0, caddy.Log())
	if err == nil || !strings.Contains(err.Error(), expectedErr.Error()) {
		t.Fatalf("expected error containing %v, got %v", expectedErr, err)
	}
}

