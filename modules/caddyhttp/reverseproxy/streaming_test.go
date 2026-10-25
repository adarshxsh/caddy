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

type safeBufferConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBufferConn) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (s *safeBufferConn) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBufferConn) Close() error {
	return nil
}

func TestSyncReadWriteCloser(t *testing.T) {
	rawConn := &safeBufferConn{}
	syncedConn := newSyncReadWriteCloser(rawConn)

	// Ensure wrapping idempotency
	if newSyncReadWriteCloser(syncedConn) != syncedConn {
		t.Fatal("newSyncReadWriteCloser should return existing syncReadWriteCloser as-is")
	}

	var wg sync.WaitGroup
	// Start concurrent payload writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := []byte("payload data from goroutine\n")
			for j := 0; j < 100; j++ {
				_, err := syncedConn.Write(data)
				if err != nil {
					t.Errorf("write error: %v", err)
				}
			}
		}(i)
	}

	// Start concurrent close control writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(isClient bool) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = writeCloseControl(syncedConn, isClient)
			}
		}(i%2 == 0)
	}

	wg.Wait()
}

func TestConcurrentConnectionWriteAndClose(t *testing.T) {
	h := &Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	rawConn := &safeBufferConn{}
	var closeCalled bool
	gracefulClose := func() error {
		closeCalled = true
		return writeCloseControl(rawConn, false)
	}

	del := h.registerConnection(rawConn, gracefulClose)
	defer del()

	// Verify that registered connection is wrapped with syncReadWriteCloser
	var registeredConn io.ReadWriteCloser
	h.connectionsMu.Lock()
	for c := range h.connections {
		registeredConn = c
	}
	h.connectionsMu.Unlock()

	if _, ok := registeredConn.(*syncReadWriteCloser); !ok {
		t.Fatalf("expected registered connection to be *syncReadWriteCloser, got %T", registeredConn)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Concurrent payload copier writing to the registered connection wrapper
	go func() {
		defer wg.Done()
		data := []byte("streaming payload frame data")
		for i := 0; i < 200; i++ {
			_, _ = registeredConn.Write(data)
		}
	}()

	// Concurrent closeConnections call
	go func() {
		defer wg.Done()
		_ = h.closeConnections()
	}()

	wg.Wait()

	if !closeCalled {
		t.Error("expected gracefulClose to have been called by closeConnections")
	}
}
