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

func TestNewLockedReadWriteCloser(t *testing.T) {
	if got := newLockedReadWriteCloser(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}

	buf := &bytes.Buffer{}
	rwc := nopReadWriteCloser{Reader: buf, Writer: buf}
	locked := newLockedReadWriteCloser(rwc)
	if _, ok := locked.(*lockedReadWriteCloser); !ok {
		t.Fatalf("expected *lockedReadWriteCloser, got %T", locked)
	}

	// Test idempotency
	lockedAgain := newLockedReadWriteCloser(locked)
	if lockedAgain != locked {
		t.Fatalf("expected same instance on re-wrap, got %v", lockedAgain)
	}

	// Test Unwrap
	if unwrapped, ok := locked.(interface{ Unwrap() io.ReadWriteCloser }); ok {
		if unwrapped.Unwrap() != rwc {
			t.Fatalf("Unwrap() returned %v, want %v", unwrapped.Unwrap(), rwc)
		}
	} else {
		t.Fatal("expected locked to implement Unwrap()")
	}

	// Test net.Conn wrapping
	pipeClient, pipeServer := net.Pipe()
	defer pipeClient.Close()
	defer pipeServer.Close()

	lockedPipe := newLockedReadWriteCloser(pipeClient)
	if _, ok := lockedPipe.(*lockedConn); !ok {
		t.Fatalf("expected *lockedConn for net.Conn input, got %T", lockedPipe)
	}

	// Test idempotency on lockedConn
	lockedPipeAgain := newLockedReadWriteCloser(lockedPipe)
	if lockedPipeAgain != lockedPipe {
		t.Fatalf("expected same instance on re-wrap of lockedConn, got %v", lockedPipeAgain)
	}

	if unwrapped, ok := lockedPipe.(interface{ Unwrap() io.ReadWriteCloser }); ok {
		if unwrapped.Unwrap() != pipeClient {
			t.Fatalf("Unwrap() returned %v, want %v", unwrapped.Unwrap(), pipeClient)
		}
	} else {
		t.Fatal("expected lockedPipe to implement Unwrap()")
	}
}

func TestLockedReadWriteCloserConcurrentWrites(t *testing.T) {
	var mu sync.Mutex
	var totalBytes int
	mockWriter := &testSyncWriter{
		onWrite: func(p []byte) {
			mu.Lock()
			totalBytes += len(p)
			mu.Unlock()
		},
	}

	rwc := nopReadWriteCloser{Writer: mockWriter}
	locked := newLockedReadWriteCloser(rwc)

	const numGoroutines = 50
	const writesPerGoroutine = 100
	data := []byte("1234567890")

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				n, err := locked.Write(data)
				if err != nil || n != len(data) {
					t.Errorf("Write error: n=%d err=%v", n, err)
				}
			}
		}()
	}

	wg.Wait()

	expectedTotal := numGoroutines * writesPerGoroutine * len(data)
	mu.Lock()
	defer mu.Unlock()
	if totalBytes != expectedTotal {
		t.Fatalf("totalBytes = %d, want %d", totalBytes, expectedTotal)
	}
}

func TestWebSocketGracefulCloseConcurrentWrite(t *testing.T) {
	pipeClient, pipeServer := net.Pipe()
	defer pipeClient.Close()
	defer pipeServer.Close()

	lockedClient := newLockedReadWriteCloser(pipeClient)

	// Read in background on pipeServer
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := pipeServer.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Concurrent payload writers
	const numWriters = 10
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := []byte("websocket payload data chunk")
			for {
				select {
				case <-stopCh:
					return
				default:
					_, _ = lockedClient.Write(data)
				}
			}
		}()
	}

	// Concurrent graceful close control frame writes
	for i := 0; i < 5; i++ {
		err := writeCloseControl(lockedClient, true)
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("writeCloseControl error: %v", err)
		}
		err = writeCloseControl(lockedClient, false)
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("writeCloseControl error: %v", err)
		}
	}

	close(stopCh)
	wg.Wait()
}

type testSyncWriter struct {
	onWrite func(p []byte)
}

func (w *testSyncWriter) Write(p []byte) (int, error) {
	if w.onWrite != nil {
		w.onWrite(p)
	}
	return len(p), nil
}

