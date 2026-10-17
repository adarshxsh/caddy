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

func TestLockedReadWriteCloserConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	mockConn := nopReadWriteCloser{
		Reader: strings.NewReader(""),
		Writer: &buf,
	}

	locked := &lockedReadWriteCloser{
		ReadWriteCloser: mockConn,
	}

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				data := []byte("test")
				_, err := locked.Write(data)
				if err != nil {
					t.Errorf("write error: %v", err)
				}
			}
		}(i)
	}

	// Concurrently invoke writeCloseControl to simulate graceful shutdown while streaming
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := writeCloseControl(locked, true)
		if err != nil {
			t.Errorf("writeCloseControl error: %v", err)
		}
	}()

	wg.Wait()

	expectedMinLen := workers*iterations*4 + 2 // payload plus close control frame
	if buf.Len() < expectedMinLen {
		t.Fatalf("buffer len = %d, want at least %d", buf.Len(), expectedMinLen)
	}
}

func TestLockedReadWriteCloserReadWriteClose(t *testing.T) {
	var buf bytes.Buffer
	reader := strings.NewReader("hello world")
	mockConn := nopReadWriteCloser{
		Reader: reader,
		Writer: &buf,
	}

	locked := &lockedReadWriteCloser{
		ReadWriteCloser: mockConn,
	}

	// Test Write
	n, err := locked.Write([]byte("foo"))
	if err != nil || n != 3 {
		t.Fatalf("Write() = %d, %v; want 3, nil", n, err)
	}
	if buf.String() != "foo" {
		t.Fatalf("buf = %q, want %q", buf.String(), "foo")
	}

	// Test Read
	readBuf := make([]byte, 5)
	nr, err := locked.Read(readBuf)
	if err != nil || nr != 5 {
		t.Fatalf("Read() = %d, %v; want 5, nil", nr, err)
	}
	if string(readBuf) != "hello" {
		t.Fatalf("readBuf = %q, want %q", string(readBuf), "hello")
	}

	// Test Close
	if err := locked.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
}
