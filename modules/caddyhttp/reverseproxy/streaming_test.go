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
	key, err := newMaskKey()
	if err != nil {
		t.Fatalf("newMaskKey() error = %v", err)
	}
	// Check that the returned key is a 4-byte array and crypto/rand populated bytes
	if len(key) != 4 {
		t.Fatalf("len(key) = %d, want 4", len(key))
	}
}

func TestWriteCloseControlClient(t *testing.T) {
	var buf bytes.Buffer
	err := writeCloseControl(&buf, true)
	if err != nil {
		t.Fatalf("writeCloseControl(client) error = %v", err)
	}

	data := buf.Bytes()
	// Header (2) + Mask Key (4) + Payload (2: status code 1001) = 8 bytes
	if len(data) != 8 {
		t.Fatalf("writeCloseControl client length = %d, want 8", len(data))
	}

	if data[0] != 0x88 { // finalBit (0x80) | closeMessage (0x08)
		t.Errorf("header byte 0 = 0x%x, want 0x88", data[0])
	}
	if data[1] != 0x82 { // maskBit (0x80) | length (2)
		t.Errorf("header byte 1 = 0x%x, want 0x82", data[1])
	}

	key := [4]byte{data[2], data[3], data[4], data[5]}
	payload := []byte{data[6], data[7]}
	for i := range payload {
		payload[i] ^= key[i%4]
	}

	wantPayload := []byte{1001 >> 8, 1001 & 0xff}
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("unmasked payload = %v, want %v", payload, wantPayload)
	}
}

func TestWriteCloseControlServer(t *testing.T) {
	var buf bytes.Buffer
	err := writeCloseControl(&buf, false)
	if err != nil {
		t.Fatalf("writeCloseControl(server) error = %v", err)
	}

	data := buf.Bytes()
	// Header (2) + Payload (2: status code 1001) = 4 bytes
	if len(data) != 4 {
		t.Fatalf("writeCloseControl server length = %d, want 4", len(data))
	}

	if data[0] != 0x88 {
		t.Errorf("header byte 0 = 0x%x, want 0x88", data[0])
	}
	if data[1] != 0x02 { // unmasked, length 2
		t.Errorf("header byte 1 = 0x%x, want 0x02", data[1])
	}

	wantPayload := []byte{1001 >> 8, 1001 & 0xff}
	if !bytes.Equal(data[2:], wantPayload) {
		t.Errorf("payload = %v, want %v", data[2:], wantPayload)
	}
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestWriteCloseControlWriterError(t *testing.T) {
	err := writeCloseControl(errWriter{}, true)
	if err != io.ErrClosedPipe {
		t.Errorf("writeCloseControl error = %v, want %v", err, io.ErrClosedPipe)
	}
}
