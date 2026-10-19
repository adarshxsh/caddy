package reverseproxy

import (
	"bytes"
	"io"
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

	buf, poolBuf := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}
	if poolBuf != nil {
		t.Fatalf("expected nil poolBuf for custom buffer size, got %v", poolBuf)
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
	buf, poolBuf := copier.buffer()
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
	if poolBuf == nil {
		t.Fatalf("expected non-nil poolBuf for default buffer size")
	}
	streamingBufPool.Put(poolBuf)
}

func TestSwitchProtocolCopierStreamingBufPool(t *testing.T) {
	// Put a sentinel buffer into streamingBufPool to track borrowing and returning
	sentinel := make([]byte, defaultBufferSize)
	sentinel[0] = 0xAA
	sentinel[1] = 0xBB
	streamingBufPool.Put(&sentinel)

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	var dstBackend bytes.Buffer
	var dstUser bytes.Buffer

	copier := switchProtocolCopier{
		user:    nopReadWriteCloser{Reader: strings.NewReader("to backend"), Writer: &dstUser},
		backend: nopReadWriteCloser{Reader: strings.NewReader("from backend"), Writer: &dstBackend},
		wg:      &wg,
		// bufferSize is 0, so defaultBufferSize and streamingBufPool should be used
	}

	wg.Add(2)
	go copier.copyToBackend(errc)
	go copier.copyFromBackend(errc)
	wg.Wait()

	for range 2 {
		if err := <-errc; err != nil {
			t.Fatalf("copy error = %v", err)
		}
	}

	if got := dstBackend.String(); got != "to backend" {
		t.Fatalf("copied to backend = %q, want %q", got, "to backend")
	}
	if got := dstUser.String(); got != "from backend" {
		t.Fatalf("copied from backend = %q, want %q", got, "from backend")
	}

	// Verify that buffers were returned to streamingBufPool
	returned1 := streamingBufPool.Get().(*[]byte)
	returned2 := streamingBufPool.Get().(*[]byte)
	if len(*returned1) != defaultBufferSize || len(*returned2) != defaultBufferSize {
		t.Fatalf("returned buffers do not match defaultBufferSize")
	}
	// Return them back to sync.Pool
	streamingBufPool.Put(returned1)
	streamingBufPool.Put(returned2)
}

func TestSwitchProtocolCopierCustomBufferSizeFallback(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("custom buffer")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 128,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "custom buffer" {
		t.Fatalf("copied data = %q, want %q", got, "custom buffer")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
