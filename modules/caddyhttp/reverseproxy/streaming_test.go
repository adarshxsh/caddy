package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

type halfCloseTestConn struct {
	net.Conn
	mu               sync.Mutex
	closeWriteCalled bool
	closed           bool
}

func newHalfCloseTestConn(c net.Conn) *halfCloseTestConn {
	return &halfCloseTestConn{Conn: c}
}

func (c *halfCloseTestConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWriteCalled = true
	c.mu.Unlock()
	return nil
}

func (c *halfCloseTestConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *halfCloseTestConn) isCloseWriteCalled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWriteCalled
}

func (c *halfCloseTestConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func newTestHandler() *Handler {
	return &Handler{
		logger:        zap.NewNop(),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
}

type hijackResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.brw, nil
}

func tcpPipe() (net.Conn, net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	ch := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		ch <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	select {
	case server := <-ch:
		return client, server, nil
	case err := <-errCh:
		client.Close()
		return nil, nil, err
	}
}

func TestHandleUpgradeResponseClientHalfClose(t *testing.T) {
	clientSide, proxyUserConn, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer clientSide.Close()

	proxyBackConn, backendSide, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer backendSide.Close()

	userWrapped := newHalfCloseTestConn(proxyUserConn)
	backWrapped := newHalfCloseTestConn(proxyBackConn)

	h := newTestHandler()
	logger := zap.NewNop()
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resHeader := make(http.Header)
	resHeader.Set("Connection", "Upgrade")
	resHeader.Set("Upgrade", "websocket")
	res := &http.Response{StatusCode: 101, Header: resHeader, Body: backWrapped}
	rw := &hijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userWrapped,
		brw:            bufio.NewReadWriter(bufio.NewReader(userWrapped), bufio.NewWriter(userWrapped)),
	}

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	// Step 1: Client writes upload data and half-closes its write side.
	const uploadPayload = "client upload payload"
	go func() {
		_, _ = clientSide.Write([]byte(uploadPayload))
		if cw, ok := clientSide.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = clientSide.Close()
		}
	}()

	// Step 2: Backend reads client upload data from proxy.
	readBuf := make([]byte, len(uploadPayload))
	_, err = io.ReadFull(backendSide, readBuf)
	if err != nil {
		t.Fatalf("backend failed to read client upload payload: %v", err)
	}
	if string(readBuf) != uploadPayload {
		t.Fatalf("backend got %q, want %q", string(readBuf), uploadPayload)
	}

	// Verify CloseWrite was invoked on the backend connection when copyToBackend hit EOF.
	time.Sleep(50 * time.Millisecond)
	if !backWrapped.isCloseWriteCalled() {
		t.Errorf("expected CloseWrite to be called on backend connection after client half-close")
	}

	// Verify handleUpgradeResponse is STILL RUNNING (waiting for copyFromBackend).
	select {
	case <-done:
		t.Fatalf("handleUpgradeResponse exited early before backend stream completed")
	default:
		// Expected: still waiting for backend response stream
	}

	// Step 3: Backend sends response stream to client after client half-close.
	const responsePayload = "backend response payload"
	go func() {
		_, _ = backendSide.Write([]byte(responsePayload))
		if cw, ok := backendSide.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = backendSide.Close()
		}
	}()

	clientReadBuf := make([]byte, len(responsePayload))
	_, err = io.ReadFull(clientSide, clientReadBuf)
	if err != nil {
		t.Fatalf("client failed to read backend response payload: %v", err)
	}
	if string(clientReadBuf) != responsePayload {
		t.Fatalf("client got %q, want %q", string(clientReadBuf), responsePayload)
	}

	// Wait for handleUpgradeResponse to complete cleanly.
	select {
	case <-done:
		wg.Wait()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for handleUpgradeResponse to exit")
	}

	if !userWrapped.isCloseWriteCalled() {
		t.Errorf("expected CloseWrite to be called on client connection after backend EOF")
	}
}

func TestHandleUpgradeResponseBackendHalfClose(t *testing.T) {
	clientSide, proxyUserConn, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer clientSide.Close()

	proxyBackConn, backendSide, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer backendSide.Close()

	userWrapped := newHalfCloseTestConn(proxyUserConn)
	backWrapped := newHalfCloseTestConn(proxyBackConn)

	h := newTestHandler()
	logger := zap.NewNop()
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resHeader := make(http.Header)
	resHeader.Set("Connection", "Upgrade")
	resHeader.Set("Upgrade", "websocket")
	res := &http.Response{StatusCode: 101, Header: resHeader, Body: backWrapped}
	rw := &hijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userWrapped,
		brw:            bufio.NewReadWriter(bufio.NewReader(userWrapped), bufio.NewWriter(userWrapped)),
	}

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	// Step 1: Backend sends initial response and half-closes its write side.
	const responsePayload = "backend initial response"
	go func() {
		_, _ = backendSide.Write([]byte(responsePayload))
		if cw, ok := backendSide.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = backendSide.Close()
		}
	}()

	clientReadBuf := make([]byte, len(responsePayload))
	_, err = io.ReadFull(clientSide, clientReadBuf)
	if err != nil {
		t.Fatalf("client failed to read backend response payload: %v", err)
	}

	// Verify CloseWrite was invoked on client connection after copyFromBackend hit EOF.
	time.Sleep(50 * time.Millisecond)
	if !userWrapped.isCloseWriteCalled() {
		t.Errorf("expected CloseWrite to be called on client connection after backend half-close")
	}

	// Verify handleUpgradeResponse is STILL RUNNING (waiting for copyToBackend).
	select {
	case <-done:
		t.Fatalf("handleUpgradeResponse exited early before client upload stream completed")
	default:
		// Expected: still waiting for client upload stream
	}

	// Step 2: Client sends upload data to backend after backend half-close.
	const uploadPayload = "client delayed upload"
	go func() {
		_, _ = clientSide.Write([]byte(uploadPayload))
		if cw, ok := clientSide.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = clientSide.Close()
		}
	}()

	backReadBuf := make([]byte, len(uploadPayload))
	_, err = io.ReadFull(backendSide, backReadBuf)
	if err != nil {
		t.Fatalf("backend failed to read client upload payload: %v", err)
	}

	// Wait for handleUpgradeResponse to complete.
	select {
	case <-done:
		wg.Wait()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for handleUpgradeResponse to exit")
	}

	if !backWrapped.isCloseWriteCalled() {
		t.Errorf("expected CloseWrite to be called on backend connection after client EOF")
	}
}

type errorTestConn struct {
	*halfCloseTestConn
	readErr  error
	writeErr error
}

func (c *errorTestConn) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.halfCloseTestConn.Read(b)
}

func (c *errorTestConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.halfCloseTestConn.Write(b)
}

func TestHandleUpgradeResponseErrorTeardown(t *testing.T) {
	clientSide, proxyUserConn, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer clientSide.Close()

	proxyBackConn, backendSide, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer backendSide.Close()

	userWrapped := &errorTestConn{
		halfCloseTestConn: newHalfCloseTestConn(proxyUserConn),
		readErr:           errors.New("connection reset by peer"),
	}
	backWrapped := newHalfCloseTestConn(proxyBackConn)

	h := newTestHandler()
	logger := zap.NewNop()
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resHeader := make(http.Header)
	resHeader.Set("Connection", "Upgrade")
	resHeader.Set("Upgrade", "websocket")
	res := &http.Response{StatusCode: 101, Header: resHeader, Body: backWrapped}
	rw := &hijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userWrapped,
		brw:            bufio.NewReadWriter(bufio.NewReader(userWrapped), bufio.NewWriter(userWrapped)),
	}

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
		wg.Wait()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for handleUpgradeResponse to exit on error")
	}

	if !userWrapped.isClosed() || !backWrapped.isClosed() {
		t.Errorf("expected both connections to be closed on streaming error")
	}
}

func TestHandleUpgradeResponseRequestContextCanceled(t *testing.T) {
	clientSide, proxyUserConn, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer clientSide.Close()

	proxyBackConn, backendSide, err := tcpPipe()
	if err != nil {
		t.Fatalf("tcpPipe failed: %v", err)
	}
	defer backendSide.Close()

	userWrapped := newHalfCloseTestConn(proxyUserConn)
	backWrapped := newHalfCloseTestConn(proxyBackConn)

	h := newTestHandler()
	logger := zap.NewNop()
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resHeader := make(http.Header)
	resHeader.Set("Connection", "Upgrade")
	resHeader.Set("Upgrade", "websocket")
	res := &http.Response{StatusCode: 101, Header: resHeader, Body: backWrapped}
	rw := &hijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userWrapped,
		brw:            bufio.NewReadWriter(bufio.NewReader(userWrapped), bufio.NewWriter(userWrapped)),
	}

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		wg.Wait()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for handleUpgradeResponse to exit on context cancellation")
	}

	if !userWrapped.isClosed() || !backWrapped.isClosed() {
		t.Errorf("expected both connections to be closed on request context cancellation")
	}
}
