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

func TestSwitchProtocolCopierWriteDeadline(t *testing.T) {
	clientRead, clientWrite := net.Pipe()
	backendRead, backendWrite := net.Pipe()
	defer clientRead.Close()
	defer clientWrite.Close()
	defer backendRead.Close()
	defer backendWrite.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	copier := switchProtocolCopier{
		user:         clientWrite,
		backend:      backendRead,
		wg:           &wg,
		writeTimeout: 30 * time.Millisecond,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)

	// Backend sends data
	go func() {
		_, _ = backendWrite.Write([]byte("backend payload"))
	}()

	// Downstream client does NOT read from clientRead, causing write stall.
	// The write deadline should kick in after 30ms.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected write deadline error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for write deadline error")
	}

	select {
	case <-done:
		// wg.Wait() completed promptly
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() hung during write stall")
	}
}

func TestSwitchProtocolCopierAsymmetricBackpressure(t *testing.T) {
	clientRead, clientWrite := net.Pipe()
	backendRead, backendWrite := net.Pipe()
	defer clientRead.Close()
	defer clientWrite.Close()
	defer backendRead.Close()
	defer backendWrite.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	copier := switchProtocolCopier{
		user:         clientWrite,
		backend:      backendRead,
		wg:           &wg,
		writeTimeout: 30 * time.Millisecond,
	}

	wg.Add(2)
	go copier.copyToBackend(errc)
	go copier.copyFromBackend(errc)

	// Backend continually sends data
	go func() {
		_, _ = backendWrite.Write([]byte("frame 1"))
	}()

	// Client does NOT read from clientRead (stalled client)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error from copier during stall")
		}
		// Close connections on first error (simulating handleUpgradeResponse teardown)
		_ = clientWrite.Close()
		_ = backendRead.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for copier error during backpressure")
	}

	select {
	case <-done:
		// All goroutines cleaned up cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() hung, goroutine leak detected")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

