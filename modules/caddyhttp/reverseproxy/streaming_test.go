package reverseproxy

import (
	"bytes"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestWriteDeadlineWriter(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	writer := writeDeadlineWriter{w: c1, timeout: 50 * time.Millisecond}

	go func() {
		buf := make([]byte, 10)
		_, _ = c2.Read(buf)
	}()

	n, err := writer.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}
}

func TestSwitchProtocolCopierClientBackpressure(t *testing.T) {
	userServer, userClient := net.Pipe()
	backServer, backClient := net.Pipe()
	defer userClient.Close()
	defer backClient.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	copier := switchProtocolCopier{
		user:         userServer,
		backend:      backServer,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	wg.Add(2)
	go copier.copyToBackend(errc)
	go copier.copyFromBackend(errc)

	done := make(chan struct{})
	go func() {
		largeData := bytes.Repeat([]byte("X"), 1024)
		for {
			_, err := backClient.Write(largeData)
			if err != nil {
				break
			}
		}
		close(done)
	}()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected non-nil error due to write deadline timeout")
		}
		userServer.Close()
		backServer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for write deadline error under client backpressure")
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("wg.Wait() blocked after socket teardown")
	}
}
