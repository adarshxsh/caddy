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

func TestLockedReadWriteCloser_PassThrough(t *testing.T) {
	inner := &mockReadWriteCloser{
		readBuf:  bytes.NewBufferString("hello world"),
		writeBuf: new(bytes.Buffer),
	}
	locked := &lockedReadWriteCloser{ReadWriteCloser: inner}

	// Test Read
	readBuf := make([]byte, 5)
	n, err := locked.Read(readBuf)
	if err != nil || n != 5 || string(readBuf) != "hello" {
		t.Fatalf("Read failed: got n=%d err=%v buf=%q", n, err, readBuf)
	}

	// Test Close
	if err := locked.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !inner.closed {
		t.Fatal("expected inner connection to be closed")
	}

	// Test Unwrap
	if unwrapped := locked.Unwrap(); unwrapped != inner {
		t.Fatalf("Unwrap returned %v, want %v", unwrapped, inner)
	}
}

type atomicChunkWriter struct {
	mu     sync.Mutex
	chunks [][]byte
}

func (w *atomicChunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	w.chunks = append(w.chunks, cp)
	return len(p), nil
}

type mockReadWriteCloser struct {
	readBuf  *bytes.Buffer
	writeBuf io.Writer
	closed   bool
}

func (m *mockReadWriteCloser) Read(p []byte) (int, error) {
	if m.readBuf == nil {
		return 0, io.EOF
	}
	return m.readBuf.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (int, error) {
	if m.writeBuf == nil {
		return len(p), nil
	}
	return m.writeBuf.Write(p)
}

func (m *mockReadWriteCloser) Close() error {
	m.closed = true
	return nil
}

func TestLockedReadWriteCloser_ConcurrentWrites(t *testing.T) {
	writer := &atomicChunkWriter{}
	mock := &mockReadWriteCloser{writeBuf: writer}
	locked := &lockedReadWriteCloser{ReadWriteCloser: mock}

	const goroutines = 20
	const writesPerGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		char := byte('A' + (i % 26))
		chunk := bytes.Repeat([]byte{char}, 100)
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				n, err := locked.Write(chunk)
				if err != nil || n != len(chunk) {
					t.Errorf("Write error: %v, n=%d", err, n)
					return
				}
			}
		}()
	}

	wg.Wait()

	writer.mu.Lock()
	defer writer.mu.Unlock()

	expectedCount := goroutines * writesPerGoroutine
	if len(writer.chunks) != expectedCount {
		t.Fatalf("expected %d written chunks, got %d", expectedCount, len(writer.chunks))
	}

	// Verify each chunk is completely intact (100 identical characters)
	for i, chunk := range writer.chunks {
		if len(chunk) != 100 {
			t.Fatalf("chunk %d has length %d, want 100", i, len(chunk))
		}
		first := chunk[0]
		for j := 1; j < len(chunk); j++ {
			if chunk[j] != first {
				t.Fatalf("chunk %d interleaved/corrupted at byte %d: got %c, want %c", i, j, chunk[j], first)
			}
		}
	}
}

func TestGracefulClose_ConcurrentWrite(t *testing.T) {
	writer := &atomicChunkWriter{}
	connMock := &mockReadWriteCloser{writeBuf: writer}
	lockedConn := &lockedReadWriteCloser{ReadWriteCloser: connMock}

	h := &Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	del := h.registerConnection(lockedConn, func() error {
		return writeCloseControl(lockedConn, false)
	})
	defer del()

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Background write simulating streaming copier io.CopyBuffer
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		data := bytes.Repeat([]byte("DATA_FRAME_PAYLOAD_"), 10)
		for i := 0; i < 50; i++ {
			_, _ = lockedConn.Write(data)
		}
	}()

	// Shutdown simulating closeConnections / writeCloseControl
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = h.closeConnections()
	}()

	close(start)
	wg.Wait()

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Ensure all written chunks remain intact (either pure data frame payload or close control frame)
	closeFrameCount := 0
	dataFrameCount := 0

	for i, chunk := range writer.chunks {
		str := string(chunk)
		if strings.HasPrefix(str, "DATA_FRAME_PAYLOAD_") {
			if len(chunk)%len("DATA_FRAME_PAYLOAD_") != 0 {
				t.Fatalf("chunk %d corrupted data frame: len=%d", i, len(chunk))
			}
			dataFrameCount++
		} else if len(chunk) >= 2 && chunk[0] == 0x88 { // RFC 6455 close control frame opcode 0x8
			closeFrameCount++
		} else {
			t.Fatalf("chunk %d corrupted/interleaved frame: %v", i, chunk)
		}
	}

	if closeFrameCount == 0 {
		t.Error("expected close control frame to be sent during closeConnections")
	}
}
