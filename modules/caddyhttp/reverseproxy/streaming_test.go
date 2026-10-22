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

type mockHijackResponseWriter struct {
	header http.Header
	conn   net.Conn
	brw    *bufio.ReadWriter
}

func (m *mockHijackResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mockHijackResponseWriter) WriteHeader(statusCode int) {}

func (m *mockHijackResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

type halfCloseTrackingConn struct {
	net.Conn
	closeWriteCalled sync.Once
	cwCalled         bool
}

func (h *halfCloseTrackingConn) CloseWrite() error {
	h.closeWriteCalled.Do(func() {
		h.cwCalled = true
	})
	if tc, ok := h.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func TestDualStreamCopierAsymmetricClose(t *testing.T) {
	// Setup TCP listeners to test actual half-close net.TCPConn streams
	lnBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for backend: %v", err)
	}
	defer lnBackend.Close()

	lnClient, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for client: %v", err)
	}
	defer lnClient.Close()

	clientConnChan := make(chan net.Conn, 1)
	go func() {
		c, err := lnClient.Accept()
		if err == nil {
			clientConnChan <- c
		}
	}()

	backendConnChan := make(chan net.Conn, 1)
	go func() {
		c, err := lnBackend.Accept()
		if err == nil {
			backendConnChan <- c
		}
	}()

	clientConn, err := net.Dial("tcp", lnClient.Addr().String())
	if err != nil {
		t.Fatalf("dial client failed: %v", err)
	}
	defer clientConn.Close()

	proxyClientConn := <-clientConnChan
	defer proxyClientConn.Close()

	proxyBackConn, err := net.Dial("tcp", lnBackend.Addr().String())
	if err != nil {
		t.Fatalf("dial backend failed: %v", err)
	}
	defer proxyBackConn.Close()

	backendConn := <-backendConnChan
	defer backendConn.Close()

	proxyClientTracked := &halfCloseTrackingConn{Conn: proxyClientConn}
	proxyBackTracked := &halfCloseTrackingConn{Conn: proxyBackConn}

	rw := &mockHijackResponseWriter{
		conn: proxyClientTracked,
		brw:  bufio.NewReadWriter(bufio.NewReader(proxyClientTracked), bufio.NewWriter(proxyClientTracked)),
	}

	req := httptest.NewRequest("GET", "http://localhost/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: proxyBackTracked,
	}

	h := Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	// 1. Client writes request payload then half-closes write direction
	_, err = clientConn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if tcp, ok := clientConn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	// 2. Backend reads payload
	buf := make([]byte, 10)
	n, err := backendConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("backend read failed: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("backend expected 'ping', got %q", string(buf[:n]))
	}

	// 3. Backend slowly streams responses back to client
	messages := []string{"pong1", "pong2", "pong3"}
	for _, msg := range messages {
		time.Sleep(20 * time.Millisecond)
		_, err := backendConn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("backend stream write failed: %v", err)
		}
	}
	if tcp, ok := backendConn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	// 4. Client reads all streamed messages
	var received string
	readBuf := make([]byte, 100)
	for {
		nr, rerr := clientConn.Read(readBuf)
		if nr > 0 {
			received += string(readBuf[:nr])
		}
		if rerr != nil {
			break
		}
	}

	expected := "pong1pong2pong3"
	if received != expected {
		t.Fatalf("client received %q, expected %q", received, expected)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for copiers to finish")
	}

	wg.Wait()

	if !proxyBackTracked.cwCalled {
		t.Errorf("expected CloseWrite to be called on backend connection when client finished")
	}
	if !proxyClientTracked.cwCalled {
		t.Errorf("expected CloseWrite to be called on client connection when backend finished")
	}
}

func TestDualStreamCopierStreamTimeout(t *testing.T) {
	p1Client, p1Proxy := net.Pipe()
	defer p1Client.Close()
	defer p1Proxy.Close()

	p2Proxy, p2Backend := net.Pipe()
	defer p2Proxy.Close()
	defer p2Backend.Close()

	rw := &mockHijackResponseWriter{
		conn: p1Proxy,
		brw:  bufio.NewReadWriter(bufio.NewReader(p1Proxy), bufio.NewWriter(p1Proxy)),
	}

	req := httptest.NewRequest("GET", "http://localhost/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: p2Proxy,
	}

	h := Handler{
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	var wg sync.WaitGroup
	start := time.Now()

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
		duration := time.Since(start)
		if duration > 1*time.Second {
			t.Fatalf("handleUpgradeResponse took too long: %v", duration)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("handleUpgradeResponse failed to terminate on StreamTimeout")
	}

	wg.Wait()
}
