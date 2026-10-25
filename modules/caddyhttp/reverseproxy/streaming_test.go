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

func TestSwitchProtocolCopierGetBuffer(t *testing.T) {
	t.Run("default buffer size 0 uses pool", func(t *testing.T) {
		copier := switchProtocolCopier{}
		buf, cleanup := copier.getBuffer()
		if got := len(buf); got != defaultBufferSize {
			t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
		}
		buf[0] = 0xAB
		cleanup()

		buf2, cleanup2 := copier.getBuffer()
		if got := len(buf2); got != defaultBufferSize {
			t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
		}
		cleanup2()
	})

	t.Run("explicit default buffer size uses pool", func(t *testing.T) {
		copier := switchProtocolCopier{bufferSize: defaultBufferSize}
		buf, cleanup := copier.getBuffer()
		if got := len(buf); got != defaultBufferSize {
			t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
		}
		cleanup()
	})

	t.Run("custom buffer size bypasses pool", func(t *testing.T) {
		copier := switchProtocolCopier{bufferSize: 8192}
		buf, cleanup := copier.getBuffer()
		if got := len(buf); got != 8192 {
			t.Fatalf("buffer len = %d, want 8192", got)
		}
		cleanup()
	})
}

func TestSwitchProtocolCopierCopyFromBackend(t *testing.T) {
	t.Run("default buffer size", func(t *testing.T) {
		var wg sync.WaitGroup
		var errc = make(chan error, 1)
		var dst bytes.Buffer

		copier := switchProtocolCopier{
			user:    nopReadWriteCloser{Writer: &dst},
			backend: nopReadWriteCloser{Reader: strings.NewReader("backend-data")},
			wg:      &wg,
		}

		wg.Add(1)
		go copier.copyFromBackend(errc)
		wg.Wait()

		if err := <-errc; err != nil {
			t.Fatalf("copyFromBackend() error = %v", err)
		}
		if got := dst.String(); got != "backend-data" {
			t.Fatalf("copied data = %q, want %q", got, "backend-data")
		}
	})

	t.Run("custom buffer size", func(t *testing.T) {
		var wg sync.WaitGroup
		var errc = make(chan error, 1)
		var dst bytes.Buffer

		copier := switchProtocolCopier{
			user:       nopReadWriteCloser{Writer: &dst},
			backend:    nopReadWriteCloser{Reader: strings.NewReader("backend-custom")},
			wg:         &wg,
			bufferSize: 5,
		}

		wg.Add(1)
		go copier.copyFromBackend(errc)
		wg.Wait()

		if err := <-errc; err != nil {
			t.Fatalf("copyFromBackend() error = %v", err)
		}
		if got := dst.String(); got != "backend-custom" {
			t.Fatalf("copied data = %q, want %q", got, "backend-custom")
		}
	})
}

func TestSwitchProtocolCopierCopyToBackendDefault(t *testing.T) {
	var wg sync.WaitGroup
	var errc = make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:    nopReadWriteCloser{Reader: strings.NewReader("to-backend-data")},
		backend: nopReadWriteCloser{Writer: &dst},
		wg:      &wg,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "to-backend-data" {
		t.Fatalf("copied data = %q, want %q", got, "to-backend-data")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
