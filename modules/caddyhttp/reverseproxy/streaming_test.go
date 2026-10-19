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

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

func TestNewMaskKey(t *testing.T) {
	keys := make(map[[4]byte]bool)
	for i := 0; i < 100; i++ {
		key := newMaskKey()
		keys[key] = true
	}
	if len(keys) < 90 {
		t.Fatalf("expected at least 90 unique keys out of 100, got %d", len(keys))
	}
}

func TestWriteCloseControl(t *testing.T) {
	t.Run("server mode", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, false)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}
		got := buf.Bytes()
		want := []byte{0x88, 0x02, 0x03, 0xe9}
		if !bytes.Equal(got, want) {
			t.Fatalf("writeCloseControl server mode = %v, want %v", got, want)
		}
	})

	t.Run("client mode", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}
		got := buf.Bytes()
		if len(got) != 8 {
			t.Fatalf("frame len = %d, want 8", len(got))
		}
		if got[0] != 0x88 || got[1] != 0x82 {
			t.Fatalf("frame header = [%x %x], want [88 82]", got[0], got[1])
		}

		var key [4]byte
		copy(key[:], got[2:6])

		unmasked := []byte{
			got[6] ^ key[0],
			got[7] ^ key[1],
		}
		wantPayload := []byte{0x03, 0xe9}
		if !bytes.Equal(unmasked, wantPayload) {
			t.Fatalf("unmasked payload = %x, want %x", unmasked, wantPayload)
		}
	})
}
