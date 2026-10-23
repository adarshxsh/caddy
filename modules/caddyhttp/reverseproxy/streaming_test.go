package reverseproxy

import (
	"bytes"
	"errors"
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

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Read(p)
}

func (s *safeBuffer) Close() error { return nil }

func TestSyncWriterConcurrentWriteAndClose(t *testing.T) {
	sb := &safeBuffer{}
	sw := newSyncWriter(sb)

	var wg sync.WaitGroup
	const numWriters = 10
	const writesPerGoroutine = 100

	start := make(chan struct{})

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data := []byte("data-chunk-12345")
			for j := 0; j < writesPerGoroutine; j++ {
				_, err := sw.Write(data)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("expected net.ErrClosed after close, got %v", err)
					}
					return
				}
				time.Sleep(10 * time.Microsecond)
			}
		}()
	}

	close(start)
	time.Sleep(1 * time.Millisecond)

	// Send WebSocket close control frame concurrently while writers are active
	if err := writeCloseControl(sw, false); err != nil {
		t.Fatalf("writeCloseControl error: %v", err)
	}

	// Verify that any write immediately following writeCloseControl returns net.ErrClosed
	_, err := sw.Write([]byte("post-close-data"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed for write after writeCloseControl, got %v", err)
	}

	wg.Wait()
}

func TestSyncWriterClose(t *testing.T) {
	sb := &safeBuffer{}
	sw := newSyncWriter(sb)

	if err := sw.Close(); err != nil {
		t.Fatalf("unexpected Close error: %v", err)
	}

	_, err := sw.Write([]byte("test"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close(), got %v", err)
	}
}

func TestSyncWriterReadWriteFullDuplex(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	sw1 := newSyncWriter(c1)
	sw2 := newSyncWriter(c2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		msg := []byte("hello from c1")
		if _, err := sw1.Write(msg); err != nil {
			t.Errorf("sw1.Write error: %v", err)
		}
		buf := make([]byte, 100)
		n, err := sw1.Read(buf)
		if err != nil {
			t.Errorf("sw1.Read error: %v", err)
		}
		if string(buf[:n]) != "hello from c2" {
			t.Errorf("sw1 read got %q, want 'hello from c2'", buf[:n])
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 100)
		n, err := sw2.Read(buf)
		if err != nil {
			t.Errorf("sw2.Read error: %v", err)
		}
		if string(buf[:n]) != "hello from c1" {
			t.Errorf("sw2 read got %q, want 'hello from c1'", buf[:n])
		}
		msg := []byte("hello from c2")
		if _, err := sw2.Write(msg); err != nil {
			t.Errorf("sw2.Write error: %v", err)
		}
	}()

	wg.Wait()
}
