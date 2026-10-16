package reverseproxy

import (
	"bytes"
	"errors"
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
	key1, err := newMaskKey()
	if err != nil {
		t.Fatalf("unexpected error from newMaskKey: %v", err)
	}

	key2, err := newMaskKey()
	if err != nil {
		t.Fatalf("unexpected error from newMaskKey: %v", err)
	}

	if len(key1) != 4 || len(key2) != 4 {
		t.Fatalf("expected 4-byte keys, got %d and %d", len(key1), len(key2))
	}

	if key1 == key2 && key1 == [4]byte{} {
		t.Fatalf("expected non-zero random keys, got identical zero keys")
	}
}

func TestNewMaskKeyError(t *testing.T) {
	oldRandRead := randRead
	randRead = func(p []byte) (n int, err error) {
		return 0, errors.New("simulated rand failure")
	}
	defer func() { randRead = oldRandRead }()

	key, err := newMaskKey()
	if err == nil {
		t.Fatalf("expected error from newMaskKey, got nil")
	}
	if key != [4]byte{} {
		t.Fatalf("expected zero key on error, got %v", key)
	}
}

func TestWriteCloseControl(t *testing.T) {
	t.Run("server mode", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := buf.Bytes()
		if len(data) != 4 {
			t.Fatalf("expected 4 bytes, got %d", len(data))
		}
		if data[0] != 0x88 {
			t.Errorf("expected b0=0x88, got 0x%x", data[0])
		}
		if data[1] != 2 {
			t.Errorf("expected b1=2, got %d", data[1])
		}
		if data[2] != 0x03 || data[3] != 0xe9 {
			t.Errorf("expected payload 0x03e9, got 0x%x%x", data[2], data[3])
		}
	})

	t.Run("client mode", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := buf.Bytes()
		if len(data) != 8 {
			t.Fatalf("expected 8 bytes, got %d", len(data))
		}
		if data[0] != 0x88 {
			t.Errorf("expected b0=0x88, got 0x%x", data[0])
		}
		if data[1] != (0x80 | 2) {
			t.Errorf("expected b1=0x82, got 0x%x", data[1])
		}

		var maskKey [4]byte
		copy(maskKey[:], data[2:6])
		payload := make([]byte, 2)
		copy(payload, data[6:8])
		maskBytes(maskKey, 0, payload)

		if payload[0] != 0x03 || payload[1] != 0xe9 {
			t.Errorf("expected unmasked payload 0x03e9, got 0x%x%x", payload[0], payload[1])
		}
	})

	t.Run("client mode rand error", func(t *testing.T) {
		oldRandRead := randRead
		randRead = func(p []byte) (n int, err error) {
			return 0, errors.New("simulated rand failure")
		}
		defer func() { randRead = oldRandRead }()

		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err == nil {
			t.Fatalf("expected error when randRead fails, got nil")
		}
		if buf.Len() != 0 {
			t.Fatalf("expected no bytes written on error, got %d bytes", buf.Len())
		}
	})
}
