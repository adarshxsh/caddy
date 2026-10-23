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
	tests := []struct {
		name       string
		bufferSize int
		wantBufLen int
	}{
		{
			name:       "default zero buffer size",
			bufferSize: 0,
			wantBufLen: defaultBufferSize,
		},
		{
			name:       "negative buffer size",
			bufferSize: -1,
			wantBufLen: defaultBufferSize,
		},
		{
			name:       "explicit default buffer size",
			bufferSize: defaultBufferSize,
			wantBufLen: defaultBufferSize,
		},
		{
			name:       "custom buffer size",
			bufferSize: 1234,
			wantBufLen: 1234,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copier := switchProtocolCopier{bufferSize: tt.bufferSize}
			buf, release := copier.getBuffer()
			if release == nil {
				t.Fatalf("getBuffer() release func is nil")
			}
			if len(buf) != tt.wantBufLen {
				t.Fatalf("getBuffer() len = %d, want %d", len(buf), tt.wantBufLen)
			}
			release()
		})
	}
}

func TestSwitchProtocolCopierCopyToBackend(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("to backend")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 0,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "to backend" {
		t.Fatalf("copied data = %q, want %q", got, "to backend")
	}
}

func TestSwitchProtocolCopierCopyFromBackend(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Writer: &dst},
		backend:    nopReadWriteCloser{Reader: strings.NewReader("from backend")},
		wg:         &wg,
		bufferSize: defaultBufferSize,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyFromBackend() error = %v", err)
	}
	if got := dst.String(); got != "from backend" {
		t.Fatalf("copied data = %q, want %q", got, "from backend")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
