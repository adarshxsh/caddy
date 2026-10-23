package reverseproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/zaptest"
)

func TestCaddyfileWebSocketKeepAlive(t *testing.T) {
	c := caddyfile.NewTestDispenser(`
	reverse_proxy {
		websocket_keepalive 15s
	}
	`)

	h := &Handler{}
	err := h.UnmarshalCaddyfile(c)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if time.Duration(h.WebSocketKeepAlive) != 15*time.Second {
		t.Fatalf("expected WebSocketKeepAlive to be 15s, got %v", h.WebSocketKeepAlive)
	}
}

func TestWebSocketKeepAlivePingGeneration(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackendConn.Close()
	defer backendConn.Close()

	req, err := http.NewRequest("GET", "http://example.com/ws", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	h := &Handler{
		WebSocketKeepAlive: caddy.Duration(50 * time.Millisecond),
		connections:        make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:      new(sync.Mutex),
	}

	logger := zaptest.NewLogger(t)
	var wg sync.WaitGroup

	rw := &mockHijackResponseWriter{
		HeaderMap: make(http.Header),
		conn:      proxyClientConn,
	}

	doneChan := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(doneChan)
	}()

	// Read Ping from client side (unmasked: opcode 0x9, len 0 -> 0x89 0x00)
	clientBuf := make([]byte, 10)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	nClient, err := io.ReadFull(clientConn, clientBuf[:2])
	if err != nil {
		t.Fatalf("failed to read ping frame from client connection: %v", err)
	}
	if nClient != 2 || clientBuf[0] != 0x89 || clientBuf[1] != 0x00 {
		t.Fatalf("unexpected ping frame on client connection: %x", clientBuf[:nClient])
	}

	// Read Ping from backend side (masked: opcode 0x9, len 0 | mask bit -> 0x89 0x80 + 4 bytes key)
	backendBuf := make([]byte, 10)
	_ = backendConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	nBackend, err := io.ReadFull(backendConn, backendBuf[:6])
	if err != nil {
		t.Fatalf("failed to read ping frame from backend connection: %v", err)
	}
	if nBackend != 6 || backendBuf[0] != 0x89 || backendBuf[1] != 0x80 {
		t.Fatalf("unexpected ping frame on backend connection: %x", backendBuf[:nBackend])
	}

	// Clean up connections
	_ = clientConn.Close()
	_ = backendConn.Close()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse did not finish after connection close")
	}
}

func TestWebSocketKeepAliveWriteFailureTeardown(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackendConn.Close()

	// Close backendConn immediately so write to backend will fail on ping
	backendConn.Close()

	req, err := http.NewRequest("GET", "http://example.com/ws", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	h := &Handler{
		WebSocketKeepAlive: caddy.Duration(20 * time.Millisecond),
		connections:        make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:      new(sync.Mutex),
	}

	logger := zaptest.NewLogger(t)
	var wg sync.WaitGroup

	rw := &mockHijackResponseWriter{
		HeaderMap: make(http.Header),
		conn:      proxyClientConn,
	}

	doneChan := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// Succeeded: failed ping write stopped copier and tore down connections cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse did not exit on ping write failure")
	}
}

func TestWebSocketKeepAliveZeroInterval(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackendConn.Close()
	defer backendConn.Close()

	req, err := http.NewRequest("GET", "http://example.com/ws", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	// Interval = 0 (disabled)
	h := &Handler{
		WebSocketKeepAlive: 0,
		connections:        make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:      new(sync.Mutex),
	}

	logger := zaptest.NewLogger(t)
	var wg sync.WaitGroup

	rw := &mockHijackResponseWriter{
		HeaderMap: make(http.Header),
		conn:      proxyClientConn,
	}

	go h.handleUpgradeResponse(logger, &wg, rw, req, res)

	// Send message from client to backend
	testMsg := []byte("hello backend")
	go func() {
		_, _ = clientConn.Write(testMsg)
	}()

	recvBuf := make([]byte, len(testMsg))
	_ = backendConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := io.ReadFull(backendConn, recvBuf)
	if err != nil {
		t.Fatalf("failed reading data on backend conn: %v", err)
	}
	if string(recvBuf[:n]) != string(testMsg) {
		t.Fatalf("expected %q, got %q", testMsg, recvBuf[:n])
	}

	_ = clientConn.Close()
	_ = backendConn.Close()
}

type mockHijackResponseWriter struct {
	HeaderMap http.Header
	conn      net.Conn
}

func (m *mockHijackResponseWriter) Header() http.Header { return m.HeaderMap }
func (m *mockHijackResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
func (m *mockHijackResponseWriter) WriteHeader(statusCode int) {}
func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn))
	return m.conn, brw, nil
}
