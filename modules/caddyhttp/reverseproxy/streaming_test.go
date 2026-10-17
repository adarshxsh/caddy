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
	k1, err := newMaskKey()
	if err != nil {
		t.Fatalf("newMaskKey() returned error: %v", err)
	}

	k2, err := newMaskKey()
	if err != nil {
		t.Fatalf("newMaskKey() returned error: %v", err)
	}

	if k1 == [4]byte{0, 0, 0, 0} && k2 == [4]byte{0, 0, 0, 0} {
		t.Fatalf("newMaskKey() produced zero keys")
	}

	if k1 == k2 {
		t.Fatalf("newMaskKey() produced duplicate sequential keys: %v", k1)
	}
}

func TestWriteCloseControl(t *testing.T) {
	t.Run("client side masked", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}

		data := buf.Bytes()
		if len(data) != 8 {
			t.Fatalf("expected 8 bytes, got %d", len(data))
		}

		if data[0] != 0x88 {
			t.Errorf("expected header byte 0 to be 0x88, got 0x%x", data[0])
		}

		if data[1] != 0x82 {
			t.Errorf("expected header byte 1 to be 0x82, got 0x%x", data[1])
		}

		var key [4]byte
		copy(key[:], data[2:6])

		if key == [4]byte{0, 0, 0, 0} {
			t.Errorf("mask key should be non-zero")
		}

		payload := make([]byte, 2)
		copy(payload, data[6:8])
		maskBytes(key, 0, payload)

		if payload[0] != 0x03 || payload[1] != 0xe9 {
			t.Errorf("expected unmasked status 1001 (0x03, 0xe9), got (0x%x, 0x%x)", payload[0], payload[1])
		}
	})

	t.Run("server side unmasked", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, false)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}

		data := buf.Bytes()
		if len(data) != 4 {
			t.Fatalf("expected 4 bytes, got %d", len(data))
		}

		if data[0] != 0x88 {
			t.Errorf("expected header byte 0 to be 0x88, got 0x%x", data[0])
		}

		if data[1] != 0x02 {
			t.Errorf("expected header byte 1 to be 0x02, got 0x%x", data[1])
		}

		if data[2] != 0x03 || data[3] != 0xe9 {
			t.Errorf("expected status 1001 (0x03, 0xe9), got (0x%x, 0x%x)", data[2], data[3])
		}
	})
}

