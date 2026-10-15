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

func TestLockedWriteCloser(t *testing.T) {
	var buf bytes.Buffer
	mock := &nopReadWriteCloser{Writer: &buf}
	lwc := &lockedWriteCloser{ReadWriteCloser: mock}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lwc.Write([]byte("test"))
			if err != nil {
				t.Errorf("unexpected write error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := buf.String(); len(got) != 40 {
		t.Fatalf("expected length 40, got %d", len(got))
	}
}

func TestConcurrentWriteCloseControl(t *testing.T) {
	var buf bytes.Buffer
	mock := &nopReadWriteCloser{Writer: &buf}
	conn := &lockedWriteCloser{ReadWriteCloser: mock}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: active stream write (simulating io.CopyBuffer)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, _ = conn.Write([]byte("stream-data"))
		}
	}()

	// Goroutine 2: graceful close handler write
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_ = writeCloseControl(conn, true)
		}
	}()

	wg.Wait()
}
