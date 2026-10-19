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
	"go.uber.org/zap"
)

func newTestHandler() *Handler {
	return &Handler{
		logger:        zap.NewNop(),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
}

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

func createTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	connCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- c.(*net.TCPConn)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	serverConn := <-connCh
	return clientConn.(*net.TCPConn), serverConn
}

func TestHandleUpgradeResponse_HalfCloseClientToBackend(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)

	h := newTestHandler()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}

	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// 1. Client sends request data then half-closes write side
	reqPayload := "hello backend"
	if _, err := clientConn.Write([]byte(reqPayload)); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite failed: %v", err)
	}

	// 2. Backend reads request payload until EOF
	gotReq, err := io.ReadAll(backendConn)
	if err != nil {
		t.Fatalf("backend read failed: %v", err)
	}
	if string(gotReq) != reqPayload {
		t.Fatalf("backend got %q, want %q", string(gotReq), reqPayload)
	}

	// 3. Backend sends response payload back to client
	resPayload := "hello client"
	if _, err := backendConn.Write([]byte(resPayload)); err != nil {
		t.Fatalf("backend write failed: %v", err)
	}
	if err := backendConn.CloseWrite(); err != nil {
		t.Fatalf("backend CloseWrite failed: %v", err)
	}

	// 4. Client reads response payload until EOF
	gotRes, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(gotRes) != resPayload {
		t.Fatalf("client got %q, want %q", string(gotRes), resPayload)
	}

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for completion")
	}
}

func TestHandleUpgradeResponse_HalfCloseBackendToClient(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)

	h := newTestHandler()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}

	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// 1. Backend sends response payload first then half-closes
	resPayload := "response from backend"
	if _, err := backendConn.Write([]byte(resPayload)); err != nil {
		t.Fatalf("backend write failed: %v", err)
	}
	if err := backendConn.CloseWrite(); err != nil {
		t.Fatalf("backend CloseWrite failed: %v", err)
	}

	// 2. Client receives response payload and EOF
	buf := make([]byte, len(resPayload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(buf) != resPayload {
		t.Fatalf("client got %q, want %q", string(buf), resPayload)
	}

	// 3. Client finishes sending request payload to backend
	reqPayload := "final client payload"
	if _, err := clientConn.Write([]byte(reqPayload)); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite failed: %v", err)
	}

	// 4. Backend reads remaining request payload
	gotReq, err := io.ReadAll(backendConn)
	if err != nil {
		t.Fatalf("backend read failed: %v", err)
	}
	if string(gotReq) != reqPayload {
		t.Fatalf("backend got %q, want %q", string(gotReq), reqPayload)
	}

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for completion")
	}
}

func TestHandleUpgradeResponse_WebSocketCloseControlFrame(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)

	h := newTestHandler()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Client closes send stream immediately
	clientConn.CloseWrite()

	// Backend should read WebSocket close frame (starts with 0x88)
	buf := make([]byte, 100)
	n, err := backendConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("backend read failed: %v", err)
	}
	if n < 2 {
		t.Fatalf("expected websocket control frame, got %d bytes", n)
	}
	// Check opcode for close frame: 0x88 (FIN + Opcode 8)
	if buf[0] != 0x88 {
		t.Fatalf("expected opcode 0x88 (close frame), got 0x%x", buf[0])
	}

	backendConn.CloseWrite()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out")
	}
}

func TestHandleUpgradeResponse_FatalErrorAbort(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)

	h := newTestHandler()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}

	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Force an ungraceful TCP RST on clientConn to trigger read error on proxyFront
	_ = clientConn.SetLinger(0)
	clientConn.Close()

	select {
	case <-done:
		// Verify backendConn is also closed by abort
		buf := make([]byte, 10)
		_, err := backendConn.Read(buf)
		if err == nil {
			t.Fatal("expected backendConn to be closed by proxy abort")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out on fatal error")
	}
}

func TestHandleUpgradeResponse_StreamTimeout(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	h := newTestHandler()
	h.StreamTimeout = caddy.Duration(50 * time.Millisecond)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}

	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Don't send anything; wait for timeout
	select {
	case <-done:
		// Connections should be closed due to timeout
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for StreamTimeout")
	}
}

func TestHandleUpgradeResponse_ContextCancellation(t *testing.T) {
	clientConn, proxyFront := createTCPPair(t)
	proxyBack, backendConn := createTCPPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBack,
	}

	h := newTestHandler()
	recorder := httptest.NewRecorder()
	rw := &dummyHijacker{ResponseRecorder: recorder, conn: proxyFront}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Cancel context while stream is idle
	cancel()

	select {
	case <-done:
		// Success: canceled request unblocked and cleaned up both streams
	case <-time.After(3 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for context cancellation")
	}
}

type dummyHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (d *dummyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(d.conn), bufio.NewWriter(d.conn))
	return d.conn, brw, nil
}

func (d *dummyHijacker) Unwrap() http.ResponseWriter {
	return d.ResponseRecorder
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
