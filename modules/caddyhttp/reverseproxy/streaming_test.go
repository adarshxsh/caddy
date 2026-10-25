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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

func TestWritePingControl(t *testing.T) {
	// Client-facing frame (isClient = false): unmasked
	bufClient := new(bytes.Buffer)
	err := writePingControl(bufClient, false, []byte("ping"))
	if err != nil {
		t.Fatalf("writePingControl client failed: %v", err)
	}
	b := bufClient.Bytes()
	if len(b) != 2+4 {
		t.Fatalf("unexpected unmasked ping frame length: %d", len(b))
	}
	if b[0] != 0x89 {
		t.Fatalf("expected opcode 0x89 for ping frame, got 0x%x", b[0])
	}
	if b[1] != 4 {
		t.Fatalf("expected payload length 4, got %d", b[1])
	}
	if string(b[2:]) != "ping" {
		t.Fatalf("expected payload 'ping', got %q", string(b[2:]))
	}

	// Backend-bound frame (isClient = true): masked
	bufBack := new(bytes.Buffer)
	err = writePingControl(bufBack, true, []byte("ping"))
	if err != nil {
		t.Fatalf("writePingControl backend failed: %v", err)
	}
	bb := bufBack.Bytes()
	if len(bb) != 2+4+4 {
		t.Fatalf("unexpected masked ping frame length: %d", len(bb))
	}
	if bb[0] != 0x89 {
		t.Fatalf("expected opcode 0x89 for ping frame, got 0x%x", bb[0])
	}
	if bb[1] != (4 | 0x80) {
		t.Fatalf("expected length 4 | 0x80 (0x84), got 0x%x", bb[1])
	}
}

func TestCaddyfileWebSocketPingInterval(t *testing.T) {
	caddyfileSnippet := `reverse_proxy localhost:8080 {
		websocket_ping_interval 15s
	}`
	d := caddyfile.NewTestDispenser(caddyfileSnippet)
	var h Handler
	err := h.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if time.Duration(h.WebSocketPingInterval) != 15*time.Second {
		t.Fatalf("expected 15s websocket_ping_interval, got %v", h.WebSocketPingInterval)
	}
}

func TestWebSocketPingIntervalValidation(t *testing.T) {
	h := &Handler{
		WebSocketPingInterval: caddy.Duration(-5 * time.Second),
	}
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}
	err = h.Provision(ctx)
	if err == nil {
		t.Fatalf("expected error for negative websocket_ping_interval, got nil")
	}
	if !strings.Contains(err.Error(), "websocket_ping_interval cannot be negative") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestWebSocketPingKeepaliveResponsivePeers(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackConn.Close()
	defer serverConn.Close()

	h := &Handler{
		WebSocketPingInterval: caddy.Duration(40 * time.Millisecond),
		connections:           make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:         new(sync.Mutex),
		logger:                zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	// Read and respond with Pong frames on client side
	var pingsReceivedClient int
	var pingsReceivedServer int
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			_ = clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := clientConn.Read(buf)
			if err != nil {
				return
			}
			if n >= 2 && buf[0] == 0x89 { // Ping opcode
				pingsReceivedClient++
				// Send Pong frame back
				pongFrame := []byte{0x8A, 0x00}
				_, _ = clientConn.Write(pongFrame)
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			_ = serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			if n >= 2 && buf[0] == 0x89 { // Ping opcode
				pingsReceivedServer++
				// Send Pong frame back
				pongFrame := []byte{0x8A, 0x80, 0, 0, 0, 0}
				_, _ = serverConn.Write(pongFrame)
			}
		}
	}()

	var proxyWg sync.WaitGroup
	// Run handleUpgradeResponse with mocked hijacker ResponseWriter
	rw := &mockHijackResponseWriter{Conn: proxyClientConn}

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &proxyWg, rw, req, res)
	}()

	// Allow keepalive loop to run for 150ms (3 ping cycles)
	time.Sleep(150 * time.Millisecond)

	if pingsReceivedClient == 0 || pingsReceivedServer == 0 {
		t.Fatalf("expected periodic Ping frames, got client pings=%d, server pings=%d",
			pingsReceivedClient, pingsReceivedServer)
	}

	proxyClientConn.Close()
	proxyBackConn.Close()
	wg.Wait()
}

func TestWebSocketPingUnresponsivePeerClosure(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackConn.Close()
	defer serverConn.Close()

	h := &Handler{
		WebSocketPingInterval: caddy.Duration(30 * time.Millisecond),
		connections:           make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:         new(sync.Mutex),
		logger:                zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	// Neither client nor server send Pong or data back!
	// We drain incoming reads so unbuffered net.Pipe writes do not block.
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	var proxyWg sync.WaitGroup
	rw := &mockHijackResponseWriter{Conn: proxyClientConn}

	doneChan := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &proxyWg, rw, req, res)
		close(doneChan)
	}()

	// Wait up to 300ms for connection closure due to idle deadline
	select {
	case <-doneChan:
		// Connection closed as expected when peers were unresponsive
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected unresponsive connection to be closed within deadline")
	}
}

func TestNonWebSocketPingBypass(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientConn.Close()
	defer proxyBackConn.Close()
	defer serverConn.Close()

	h := &Handler{
		WebSocketPingInterval: caddy.Duration(30 * time.Millisecond),
		connections:           make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:         new(sync.Mutex),
		logger:                zap.NewNop(),
	}

	// Non-WebSocket upgrade request (e.g. SSH or raw TCP upgrade)
	req := httptest.NewRequest("GET", "http://example.com/ssh", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "ssh")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "ssh")

	var pingsReceived int
	go func() {
		buf := make([]byte, 1024)
		for {
			_ = clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := clientConn.Read(buf)
			if err != nil {
				return
			}
			if n >= 2 && buf[0] == 0x89 {
				pingsReceived++
			}
		}
	}()

	var proxyWg sync.WaitGroup
	rw := &mockHijackResponseWriter{Conn: proxyClientConn}

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &proxyWg, rw, req, res)
	}()

	time.Sleep(100 * time.Millisecond)

	if pingsReceived > 0 {
		t.Fatalf("expected 0 ping frames for non-websocket upgrade, got %d", pingsReceived)
	}

	proxyClientConn.Close()
	proxyBackConn.Close()
}

type mockHijackResponseWriter struct {
	httptest.ResponseRecorder
	Conn net.Conn
}

func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(m.Conn), bufio.NewWriter(m.Conn))
	return m.Conn, brw, nil
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
