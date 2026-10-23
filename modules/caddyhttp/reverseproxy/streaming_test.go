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
	nonZeroCount := 0

	for i := 0; i < 100; i++ {
		key := newMaskKey()
		if key != [4]byte{0, 0, 0, 0} {
			nonZeroCount++
		}
		keys[key] = true
	}

	if nonZeroCount == 0 {
		t.Fatalf("newMaskKey produced only zero keys")
	}

	// Uniqueness check: 100 random 4-byte keys should yield at least ~90 unique keys
	if len(keys) < 90 {
		t.Errorf("newMaskKey produced too few unique keys: %d unique out of 100", len(keys))
	}
}

func TestWriteCloseControl(t *testing.T) {
	t.Run("client frame masked", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, true)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}

		data := buf.Bytes()
		// Expect: 2 bytes header + 4 bytes mask key + 2 bytes payload = 8 bytes
		if len(data) != 8 {
			t.Fatalf("expected 8 bytes, got %d", len(data))
		}

		// Opcode 8 (close) | Final bit (0x80) => 0x88
		if data[0] != 0x88 {
			t.Errorf("expected byte 0 to be 0x88, got 0x%02x", data[0])
		}

		// Mask bit (0x80) | len 2 => 0x82
		if data[1] != 0x82 {
			t.Errorf("expected byte 1 to be 0x82, got 0x%02x", data[1])
		}

		var maskKey [4]byte
		copy(maskKey[:], data[2:6])

		// Payload is status code 1001 (0x03e9)
		maskedPayload := data[6:8]
		unmaskedPayload := make([]byte, 2)
		for i := 0; i < 2; i++ {
			unmaskedPayload[i] = maskedPayload[i] ^ maskKey[i%4]
		}

		expectedPayload := []byte{1001 >> 8, 1001 & 0xff}
		if !bytes.Equal(unmaskedPayload, expectedPayload) {
			t.Errorf("expected unmasked payload %v, got %v", expectedPayload, unmaskedPayload)
		}
	})

	t.Run("server frame unmasked", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeCloseControl(&buf, false)
		if err != nil {
			t.Fatalf("writeCloseControl failed: %v", err)
		}

		data := buf.Bytes()
		// Expect: 2 bytes header + 2 bytes payload = 4 bytes
		if len(data) != 4 {
			t.Fatalf("expected 4 bytes, got %d", len(data))
		}

		if data[0] != 0x88 {
			t.Errorf("expected byte 0 to be 0x88, got 0x%02x", data[0])
		}

		if data[1] != 0x02 {
			t.Errorf("expected byte 1 to be 0x02, got 0x%02x", data[1])
		}

		expectedPayload := []byte{1001 >> 8, 1001 & 0xff}
		if !bytes.Equal(data[2:4], expectedPayload) {
			t.Errorf("expected payload %v, got %v", expectedPayload, data[2:4])
		}
	})
}

