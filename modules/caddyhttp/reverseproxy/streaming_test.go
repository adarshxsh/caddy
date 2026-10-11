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

	buf, cleanup := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}
	cleanup()

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
	for _, tc := range []struct {
		name       string
		bufferSize int
	}{
		{name: "zero default", bufferSize: 0},
		{name: "negative default", bufferSize: -1},
		{name: "explicit default", bufferSize: defaultBufferSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copier := switchProtocolCopier{bufferSize: tc.bufferSize}
			buf, cleanup := copier.buffer()
			if got := len(buf); got != defaultBufferSize {
				t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
			}
			if cleanup == nil {
				t.Fatalf("expected non-nil cleanup function")
			}
			cleanup()
		})
	}
}

func TestSwitchProtocolCopierCopyFromBackend(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:    nopReadWriteCloser{Writer: &dst},
		backend: nopReadWriteCloser{Reader: strings.NewReader("world")},
		wg:      &wg,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyFromBackend() error = %v", err)
	}
	if got := dst.String(); got != "world" {
		t.Fatalf("copied data = %q, want %q", got, "world")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

func BenchmarkSwitchProtocolCopierBuffer(b *testing.B) {
	copier := switchProtocolCopier{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, cleanup := copier.buffer()
		_ = buf
		cleanup()
	}
}
