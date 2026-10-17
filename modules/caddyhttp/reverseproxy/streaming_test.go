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

	buf, release := copier.getBuffer()
	defer release()
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
	buf, release := copier.getBuffer()
	defer release()
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
}

func TestSwitchProtocolCopierGetBufferPool(t *testing.T) {
	t.Run("default buffer size uses pool", func(t *testing.T) {
		copiers := []switchProtocolCopier{
			{}, // bufferSize == 0
			{bufferSize: -1},
			{bufferSize: defaultBufferSize},
		}

		for _, c := range copiers {
			buf, release := c.getBuffer()
			if got := len(buf); got != defaultBufferSize {
				t.Fatalf("buffer len = %d, want %d for copier %+v", got, defaultBufferSize, c)
			}
			// Verify release returns buffer to streamingBufPool
			release()

			pBuf := streamingBufPool.Get().(*[]byte)
			if pBuf == nil || len(*pBuf) != defaultBufferSize {
				t.Fatalf("expected buffer from pool with size %d", defaultBufferSize)
			}
			streamingBufPool.Put(pBuf)
		}
	})

	t.Run("custom buffer size allocates directly", func(t *testing.T) {
		customSize := 8192
		copier := switchProtocolCopier{bufferSize: customSize}
		buf, release := copier.getBuffer()
		if got := len(buf); got != customSize {
			t.Fatalf("buffer len = %d, want %d", got, customSize)
		}
		// release for custom size should be no-op and not panic
		release()
	})
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
