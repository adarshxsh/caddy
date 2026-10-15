package reverseproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

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

type mockHijackResponseRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (m *mockHijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

func TestStreamTimeoutActivityReset(t *testing.T) {
	clientFront, serverFront := net.Pipe()
	clientBack, serverBack := net.Pipe()

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       serverBack,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverFront,
		brw:              bufio.NewReadWriter(bufio.NewReader(serverFront), bufio.NewWriter(serverFront)),
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	// Send periodic activity for 350ms (exceeding initial 150ms StreamTimeout)
	stopActivity := make(chan struct{})
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopActivity:
				return
			case <-ticker.C:
				_, _ = clientFront.Write([]byte("ping"))
			}
		}
	}()

	// Drain reads on clientBack to keep pipe from blocking
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := clientBack.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Wait 350ms (well over 150ms timeout)
	time.Sleep(350 * time.Millisecond)

	// Verify the handler has NOT timed out yet while active
	select {
	case <-done:
		t.Fatal("handler closed active stream prematurely")
	default:
		// Active stream is still running as expected
	}

	close(stopActivity)
	_ = clientFront.Close()
	_ = clientBack.Close()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("handler did not exit after connections were closed")
	}
}

func TestStreamTimeoutActivityResetUpstream(t *testing.T) {
	clientFront, serverFront := net.Pipe()
	clientBack, serverBack := net.Pipe()

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       serverBack,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverFront,
		brw:              bufio.NewReadWriter(bufio.NewReader(serverFront), bufio.NewWriter(serverFront)),
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	// Send periodic activity from backend to client for 350ms (exceeding initial 150ms StreamTimeout)
	stopActivity := make(chan struct{})
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopActivity:
				return
			case <-ticker.C:
				_, _ = clientBack.Write([]byte("pong"))
			}
		}
	}()

	// Drain reads on clientFront to keep pipe from blocking
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := clientFront.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Wait 350ms (well over 150ms timeout)
	time.Sleep(350 * time.Millisecond)

	// Verify the handler has NOT timed out yet while active
	select {
	case <-done:
		t.Fatal("handler closed active stream prematurely on upstream activity")
	default:
		// Active stream is still running as expected
	}

	close(stopActivity)
	_ = clientFront.Close()
	_ = clientBack.Close()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("handler did not exit after connections were closed")
	}
}

func TestStreamTimeoutIdleClose(t *testing.T) {
	clientFront, serverFront := net.Pipe()
	clientBack, serverBack := net.Pipe()

	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       serverBack,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverFront,
		brw:              bufio.NewReadWriter(bufio.NewReader(serverFront), bufio.NewWriter(serverFront)),
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	// Do NOT send any activity. The handler should time out after ~100ms.
	select {
	case <-done:
		// Success: handler timed out and closed stream
	case <-time.After(1 * time.Second):
		t.Fatal("handler did not time out idle stream")
	}

	_ = clientFront.Close()
	_ = clientBack.Close()
}
