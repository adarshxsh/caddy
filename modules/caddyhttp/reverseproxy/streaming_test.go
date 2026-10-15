package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
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

type halfCloseTestConn struct {
	io.Reader
	io.Writer
	closeWriteCalled bool
}

func (h *halfCloseTestConn) Close() error { return nil }
func (h *halfCloseTestConn) CloseWrite() error {
	h.closeWriteCalled = true
	return nil
}

func TestSwitchProtocolCopierHalfClose(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	dstConn := &halfCloseTestConn{Writer: &bytes.Buffer{}}
	srcConn := nopReadWriteCloser{Reader: strings.NewReader("data")}

	copier := switchProtocolCopier{
		user:    srcConn,
		backend: dstConn,
		wg:      &wg,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dstConn.closeWriteCalled {
		t.Fatalf("expected CloseWrite to be called on destination connection upon EOF")
	}
}

type hijackableResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	br := bufio.NewReader(h.conn)
	bw := bufio.NewWriter(h.conn)
	return h.conn, bufio.NewReadWriter(br, bw), nil
}

func TestHandleUpgradeResponseWaitBothCopiers(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer backendConn.Close()

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}
	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyClientConn,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	handlerDone := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(handlerDone)
	}()

	// 1. Client writes request message and closes client write side (half-close).
	go func() {
		_, _ = clientConn.Write([]byte("client request"))
		// net.Pipe doesn't support CloseWrite, so closing clientConn simulates EOF on proxyClientConn read side.
		_ = clientConn.Close()
	}()

	// 2. Backend reads message from backendConn.
	buf := make([]byte, 64)
	n, err := backendConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("backend read error: %v", err)
	}
	if got := string(buf[:n]); got != "client request" {
		t.Fatalf("backend got %q, want %q", got, "client request")
	}

	// Verify handler is STILL RUNNING (waiting for backend copier to complete) even though client closed.
	select {
	case <-handlerDone:
		t.Fatalf("handler exited prematurely after client EOF before backend finished")
	case <-time.After(50 * time.Millisecond):
		// Expected: handler keeps waiting for backend copier.
	}

	// 3. Backend sends response message and closes backend write side.
	_, _ = backendConn.Write([]byte("backend response"))
	_ = backendConn.Close()

	// 4. Verify handler completes naturally.
	select {
	case <-handlerDone:
		// Success!
	case <-time.After(2 * time.Second):
		t.Fatalf("handler timed out waiting for completion")
	}
}

func TestHandleUpgradeResponseTimeoutTeardown(t *testing.T) {
	_, proxyClientConn := net.Pipe()
	proxyBackendConn, _ := net.Pipe()

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
	}
	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyClientConn,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	handlerDone := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(handlerDone)
	}()

	select {
	case <-handlerDone:
		// Success: handler completed after timing out and tearing down connections.
	case <-time.After(2 * time.Second):
		t.Fatalf("handler hung and did not tear down connections on timeout")
	}
}

func TestHandleUpgradeResponseContextCanceledTeardown(t *testing.T) {
	_, proxyClientConn := net.Pipe()
	proxyBackendConn, _ := net.Pipe()

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}
	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyClientConn,
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	handlerDone := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(handlerDone)
	}()

	// Cancel context after short delay
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-handlerDone:
		// Success: handler completed after context cancellation.
	case <-time.After(2 * time.Second):
		t.Fatalf("handler hung and did not tear down connections on context cancellation")
	}
}
