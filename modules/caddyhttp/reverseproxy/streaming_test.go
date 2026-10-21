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

func TestNewMaskKey(t *testing.T) {
	keys := make(map[[4]byte]bool)
	const numIterations = 100

	for i := 0; i < numIterations; i++ {
		key := newMaskKey()
		if len(key) != 4 {
			t.Fatalf("expected 4-byte mask key, got %d bytes", len(key))
		}
		keys[key] = true
	}

	// Out of 100 random 4-byte keys, we should have generated multiple unique keys.
	if len(keys) < numIterations/2 {
		t.Fatalf("expected high randomness in mask keys, but got only %d unique keys out of %d", len(keys), numIterations)
	}
}

func TestWriteCloseControl(t *testing.T) {
	t.Run("client mode with masking", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}
		// Close frame length when masked: 2 bytes header + 4 bytes mask key + 2 bytes status code = 8 bytes
		if buf.Len() != 8 {
			t.Fatalf("expected buffer length 8, got %d", buf.Len())
		}
	})

	t.Run("server mode without masking", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, false)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}
		// Close frame length unmasked: 2 bytes header + 2 bytes status code = 4 bytes
		if buf.Len() != 4 {
			t.Fatalf("expected buffer length 4, got %d", buf.Len())
		}
	})
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
