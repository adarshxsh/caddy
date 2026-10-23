package reverseproxy

import (
	"bufio"
	"bytes"
	"errors"
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

type mockCloseWriteConn struct {
	net.Conn
	mu               sync.Mutex
	closeWriteCalled bool
}

func (m *mockCloseWriteConn) CloseWrite() error {
	m.mu.Lock()
	m.closeWriteCalled = true
	m.mu.Unlock()
	return m.Conn.Close()
}

type mockHijackResponseRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (m *mockHijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn))
	return m.conn, brw, nil
}

func createTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	var serverConn *net.TCPConn
	var acceptErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			acceptErr = err
			return
		}
		serverConn = conn.(*net.TCPConn)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("failed to accept: %v", acceptErr)
	}
	return clientConn.(*net.TCPConn), serverConn
}

func TestHandleUpgradeResponse_DualCompletion(t *testing.T) {
	clientConn, userConn := createTCPPair(t)
	backConn, serverConn := createTCPPair(t)

	h := Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             userConn,
	}

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	// Simulate client sending data then half-closing write
	go func() {
		clientConn.Write([]byte("hello from client"))
		clientConn.CloseWrite()
	}()

	// Simulate backend receiving client data then sending response and half-closing write
	go func() {
		buf := make([]byte, 100)
		n, err := serverConn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("backend read error: %v", err)
			return
		}
		if string(buf[:n]) != "hello from client" {
			t.Errorf("backend received %q, want 'hello from client'", buf[:n])
		}
		serverConn.Write([]byte("hello from backend"))
		serverConn.CloseWrite()
	}()

	// Read backend response on client side
	buf := make([]byte, 100)
	n, err := clientConn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("client read error: %v", err)
	}
	if string(buf[:n]) != "hello from backend" {
		t.Fatalf("client received %q, want 'hello from backend'", buf[:n])
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for dual completion")
	}

	wg.Wait()
}

func TestHandleUpgradeResponse_NonNilError(t *testing.T) {
	clientConn, userConn := createTCPPair(t)
	backConn, serverConn := createTCPPair(t)

	h := Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             userConn,
	}

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	// Force an unrecoverable error by abruptly closing sockets
	clientConn.Close()
	serverConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse did not exit promptly on non-nil error")
	}

	wg.Wait()
}

func TestHandleUpgradeResponse_StreamTimeout(t *testing.T) {
	clientConn, userConn := createTCPPair(t)
	backConn, serverConn := createTCPPair(t)

	defer clientConn.Close()
	defer serverConn.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             userConn,
	}

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse did not exit on StreamTimeout")
	}

	wg.Wait()
}

type noCloseWriteConn struct {
	net.Conn
}

func TestHandleUpgradeResponse_NoCloseWriteSupport(t *testing.T) {
	clientConn, uConn := createTCPPair(t)
	backConn, serverConn := createTCPPair(t)

	userConn := noCloseWriteConn{uConn}
	bConn := noCloseWriteConn{backConn}

	h := Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             userConn,
	}

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       bConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	clientConn.Write([]byte("hello"))
	clientConn.CloseWrite()

	buf := make([]byte, 100)
	n, _ := serverConn.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Fatalf("server received %q", buf[:n])
	}
	serverConn.Write([]byte("world"))
	serverConn.CloseWrite()

	n, _ = clientConn.Read(buf)
	if string(buf[:n]) != "world" {
		t.Fatalf("client received %q", buf[:n])
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out on non-CloseWrite connection")
	}

	wg.Wait()
}
