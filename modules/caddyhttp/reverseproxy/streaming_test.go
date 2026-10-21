package reverseproxy

import (
	"bytes"
	"io"
	"net"
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

func TestSyncWriterConn(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	conn := &syncWriterConn{ReadWriteCloser: nopReadWriteCloser{Reader: pr, Writer: pw}}

	const goroutines = 10
	const writesPerGoroutine = 50
	var wg sync.WaitGroup

	// Drain reader concurrently
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
		}
		close(readDone)
	}()

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				_, err := conn.Write([]byte("test-data"))
				if err != nil {
					return
				}
			}
		}()
	}

	wg.Wait()
	pw.Close()
	<-readDone
}

func TestConcurrentCloseAndStream(t *testing.T) {
	uProxy, uClient := net.Pipe()
	bProxy, bBackend := net.Pipe()

	syncUser := &syncWriterConn{ReadWriteCloser: uProxy}
	syncBack := &syncWriterConn{ReadWriteCloser: bProxy}

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := switchProtocolCopier{
		user:       syncUser,
		backend:    syncBack,
		wg:         &wg,
		bufferSize: 64,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	// Mock client goroutine: sending data and reading data
	var mockWg sync.WaitGroup
	mockWg.Add(2)
	go func() {
		defer mockWg.Done()
		for i := 0; i < 20; i++ {
			_, err := uClient.Write([]byte("hello from client"))
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer mockWg.Done()
		buf := make([]byte, 512)
		for {
			_, err := uClient.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Mock backend goroutine: sending data and reading data
	mockWg.Add(2)
	go func() {
		defer mockWg.Done()
		for i := 0; i < 20; i++ {
			_, err := bBackend.Write([]byte("hello from backend"))
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer mockWg.Done()
		buf := make([]byte, 512)
		for {
			_, err := bBackend.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Concurrently invoke writeCloseControl while streaming
	var closeWg sync.WaitGroup
	closeWg.Add(2)
	go func() {
		defer closeWg.Done()
		_ = writeCloseControl(syncUser, false)
	}()
	go func() {
		defer closeWg.Done()
		_ = writeCloseControl(syncBack, true)
	}()

	closeWg.Wait()

	_ = uClient.Close()
	_ = bBackend.Close()
	_ = uProxy.Close()
	_ = bProxy.Close()

	mockWg.Wait()
	wg.Wait()
}
