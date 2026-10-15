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

func TestSwitchProtocolCopierPoolReuse(t *testing.T) {
	copier := switchProtocolCopier{}

	buf1, release1 := copier.getBuffer()
	if len(buf1) != defaultBufferSize {
		t.Fatalf("buf1 len = %d, want %d", len(buf1), defaultBufferSize)
	}
	ptr1 := &buf1[0]
	release1()

	buf2, release2 := copier.getBuffer()
	defer release2()
	if len(buf2) != defaultBufferSize {
		t.Fatalf("buf2 len = %d, want %d", len(buf2), defaultBufferSize)
	}
	ptr2 := &buf2[0]

	if ptr1 != ptr2 {
		t.Fatalf("expected buffer reuse from pool, but got different memory addresses: %p vs %p", ptr1, ptr2)
	}

	customCopier := switchProtocolCopier{bufferSize: 1024}
	customBuf, customRelease := customCopier.getBuffer()
	defer customRelease()
	if len(customBuf) != 1024 {
		t.Fatalf("customBuf len = %d, want 1024", len(customBuf))
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
