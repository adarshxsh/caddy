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

type concurrentBufferConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *concurrentBufferConn) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (c *concurrentBufferConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	c.writes = append(c.writes, cp)
	return len(p), nil
}

func (c *concurrentBufferConn) Close() error { return nil }

func TestLockedReadWriteCloser(t *testing.T) {
	rawConn := &concurrentBufferConn{}
	locked := &lockedReadWriteCloser{ReadWriteCloser: rawConn}

	if unwrapped := locked.Unwrap(); unwrapped != rawConn {
		t.Fatalf("Unwrap() returned %v, want %v", unwrapped, rawConn)
	}

	const numGoroutines = 50
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			data := []byte(strings.Repeat(string(rune('a'+(id%26))), 64))
			for j := 0; j < writesPerGoroutine; j++ {
				n, err := locked.Write(data)
				if err != nil {
					t.Errorf("locked.Write error: %v", err)
					return
				}
				if n != len(data) {
					t.Errorf("locked.Write returned %d, want %d", n, len(data))
					return
				}
			}
		}(i)
	}

	wg.Wait()

	if len(rawConn.writes) != numGoroutines*writesPerGoroutine {
		t.Fatalf("expected %d total writes, got %d", numGoroutines*writesPerGoroutine, len(rawConn.writes))
	}
}

func TestLockedReadWriteCloser_ConcurrentWriteAndCloseControl(t *testing.T) {
	rawConn := &concurrentBufferConn{}
	locked := &lockedReadWriteCloser{ReadWriteCloser: rawConn}

	const numWriters = 10
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := []byte(strings.Repeat(string(rune('A'+id)), 128))
			for {
				select {
				case <-stopCh:
					return
				default:
					_, err := locked.Write(payload)
					if err != nil {
						t.Errorf("Write error: %v", err)
						return
					}
				}
			}
		}(i)
	}

	// Concurrent writeCloseControl calls as both client and backend
	var closeWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		closeWg.Add(2)
		go func() {
			defer closeWg.Done()
			err := writeCloseControl(locked, false)
			if err != nil {
				t.Errorf("writeCloseControl server error: %v", err)
			}
		}()
		go func() {
			defer closeWg.Done()
			err := writeCloseControl(locked, true)
			if err != nil {
				t.Errorf("writeCloseControl client error: %v", err)
			}
		}()
	}

	closeWg.Wait()
	close(stopCh)
	wg.Wait()

	// Verify that each recorded write slice is a complete payload or close control frame
	rawConn.mu.Lock()
	defer rawConn.mu.Unlock()

	for idx, w := range rawConn.writes {
		// Close frame length for server: 4 bytes (2 header + 2 '1001' status)
		// Close frame length for client: 8 bytes (2 header + 4 mask key + 2 '1001' status masked)
		// Normal payload length: 128 bytes
		if len(w) != 4 && len(w) != 8 && len(w) != 128 {
			t.Fatalf("write #%d has corrupted size %d (expected 4, 8, or 128)", idx, len(w))
		}
	}
}

func TestHandler_GracefulCloseConcurrentWithCopy(t *testing.T) {
	h := &Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	rawConn := &concurrentBufferConn{}
	lockedConn := &lockedReadWriteCloser{ReadWriteCloser: rawConn}

	graceful := func() error {
		return writeCloseControl(lockedConn, false)
	}

	delFn := h.registerConnection(lockedConn, graceful)
	defer delFn()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			select {
			case <-stopCh:
				return
			default:
				_, _ = lockedConn.Write(buf)
			}
		}
	}()

	err := h.closeConnections()
	if err != nil {
		t.Fatalf("closeConnections error: %v", err)
	}

	close(stopCh)
	wg.Wait()
}
