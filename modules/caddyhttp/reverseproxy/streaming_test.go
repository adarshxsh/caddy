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

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

func TestWritePingControl(t *testing.T) {
	// Server side (isClient = false): expect 2 bytes (0x89 0x00)
	var serverBuf bytes.Buffer
	if err := writePingControl(&serverBuf, false); err != nil {
		t.Fatalf("writePingControl(server) failed: %v", err)
	}
	serverBytes := serverBuf.Bytes()
	if len(serverBytes) != 2 {
		t.Fatalf("expected 2 bytes for server ping, got %d", len(serverBytes))
	}
	if serverBytes[0] != 0x89 {
		t.Errorf("expected opcode 0x89, got 0x%x", serverBytes[0])
	}
	if serverBytes[1] != 0x00 {
		t.Errorf("expected header byte 1 to be 0x00, got 0x%x", serverBytes[1])
	}

	// Client side (isClient = true): expect 6 bytes (0x89 0x80 + 4 mask bytes)
	var clientBuf bytes.Buffer
	if err := writePingControl(&clientBuf, true); err != nil {
		t.Fatalf("writePingControl(client) failed: %v", err)
	}
	clientBytes := clientBuf.Bytes()
	if len(clientBytes) != 6 {
		t.Fatalf("expected 6 bytes for client ping, got %d", len(clientBytes))
	}
	if clientBytes[0] != 0x89 {
		t.Errorf("expected opcode 0x89, got 0x%x", clientBytes[0])
	}
	if clientBytes[1] != 0x80 {
		t.Errorf("expected header byte 1 mask bit 0x80, got 0x%x", clientBytes[1])
	}
}

func TestSyncWriterConnConcurrentWrites(t *testing.T) {
	var dst bytes.Buffer
	conn := &syncWriterConn{ReadWriteCloser: nopReadWriteCloser{Writer: &dst}}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = conn.Write([]byte("test"))
			}
		}()
	}
	wg.Wait()

	if dst.Len() != 10*100*4 {
		t.Fatalf("expected dst length %d, got %d", 10*100*4, dst.Len())
	}
}

func TestWebSocketKeepalivePingAndDeadSocket(t *testing.T) {
	userClient, userServer := net.Pipe()
	backClient, backServer := net.Pipe()

	defer userClient.Close()
	defer backClient.Close()

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	h := &Handler{
		StreamKeepAlive: caddy.Duration(20 * time.Millisecond),
		connections:     make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:   new(sync.Mutex),
		logger:          zap.NewNop(),
	}

	var wg sync.WaitGroup

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backServer,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rec := httptest.NewRecorder()
	rw := &hijackRecorder{ResponseRecorder: rec, conn: userServer}

	upgraded := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(upgraded)
	}()

	// Read ping from user side
	buf := make([]byte, 10)
	_ = userClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := userClient.Read(buf)
	if err != nil {
		t.Fatalf("failed to read ping from user client: %v", err)
	}
	if n < 2 || buf[0] != 0x89 {
		t.Fatalf("expected ping opcode 0x89, got frame bytes: %v", buf[:n])
	}

	// Read ping from backend side
	_ = backClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = backClient.Read(buf)
	if err != nil {
		t.Fatalf("failed to read ping from back client: %v", err)
	}
	if n < 6 || buf[0] != 0x89 || buf[1] != 0x80 {
		t.Fatalf("expected client masked ping opcode 0x89 0x80, got frame bytes: %v", buf[:n])
	}

	// Close backend connection to simulate connection drop / dead socket
	_ = backClient.Close()

	// Verify that copier goroutines stop within keepalive period
	done := make(chan struct{})
	go func() {
		<-upgraded
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Copiers exited promptly
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("copier goroutines failed to stop after dead connection drop")
	}
}

func TestNonWebSocketBypassesKeepalive(t *testing.T) {
	userClient, userServer := net.Pipe()
	backClient, backServer := net.Pipe()

	defer userClient.Close()
	defer backClient.Close()

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "custom-proto")

	h := &Handler{
		StreamKeepAlive: caddy.Duration(20 * time.Millisecond),
		connections:     make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:   new(sync.Mutex),
		logger:          zap.NewNop(),
	}

	var wg sync.WaitGroup

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backServer,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "custom-proto")

	rec := httptest.NewRecorder()
	rw := &hijackRecorder{ResponseRecorder: rec, conn: userServer}

	upgraded := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(upgraded)
	}()

	// Verify no ping frames are received on non-websocket upgrade
	buf := make([]byte, 10)
	_ = userClient.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = userClient.Read(buf)
	if err == nil {
		t.Fatalf("expected read timeout for non-websocket upgrade, but received data")
	}

	_ = userClient.Close()
	_ = backClient.Close()

	<-upgraded
	wg.Wait()
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, brw, nil
}

func TestCaddyfileStreamKeepalive(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		reverse_proxy {
			stream_keepalive 15s
		}
	`)
	h := new(Handler)
	err := h.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if h.StreamKeepAlive != caddy.Duration(15*time.Second) {
		t.Fatalf("expected StreamKeepAlive 15s, got %v", h.StreamKeepAlive)
	}
}
