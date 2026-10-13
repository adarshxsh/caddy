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
	var flushCount int
	mlw := &maxLatencyWriter{
		dst: &bytes.Buffer{},
		flush: func() error {
			flushCount++
			return nil
		},
		flushPending: true,
		logger:       zap.NewNop(),
	}

	mlw.stop()

	if flushCount != 1 {
		t.Errorf("expected 1 flush on stop, got %d", flushCount)
	}
	if mlw.flushPending {
		t.Errorf("expected flushPending to be false after stop")
	}
}

func TestMaxLatencyWriterStopNoPending(t *testing.T) {
	var flushCount int
	mlw := &maxLatencyWriter{
		dst: &bytes.Buffer{},
		flush: func() error {
			flushCount++
			return nil
		},
		flushPending: true,
		logger:       zap.NewNop(),
	}

	mlw.delayedFlush()
	if flushCount != 1 {
		t.Fatalf("expected 1 flush on delayedFlush, got %d", flushCount)
	}

	mlw.stop()
	if flushCount != 1 {
		t.Errorf("expected no additional flush on stop when not pending, got total %d", flushCount)
	}
}

func TestMaxLatencyWriterStopConcurrent(t *testing.T) {
	for i := 0; i < 100; i++ {
		var flushCount atomic.Int32
		mlw := &maxLatencyWriter{
			dst: &bytes.Buffer{},
			flush: func() error {
				flushCount.Add(1)
				return nil
			},
			flushPending: true,
			logger:       zap.NewNop(),
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			mlw.delayedFlush()
		}()
		go func() {
			defer wg.Done()
			mlw.stop()
		}()
		wg.Wait()

		if got := flushCount.Load(); got != 1 {
			t.Errorf("iteration %d: expected exactly 1 flush, got %d", i, got)
		}
	}
}

func TestHandlerCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{}
	recorder := httptest.NewRecorder()
	src := strings.NewReader("hello trailing response")

	err := h.copyResponse(recorder, src, 100*time.Millisecond, caddy.Log())
	if err != nil {
		t.Fatalf("copyResponse failed: %v", err)
	}

	if got := recorder.Body.String(); got != "hello trailing response" {
		t.Errorf("expected %q, got %q", "hello trailing response", got)
	}
	if !recorder.Flushed {
		t.Errorf("expected response recorder to be flushed upon stream completion")
	}
}

