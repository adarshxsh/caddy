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

type hijackableResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
	r    *bufio.Reader
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(h.r, bufio.NewWriter(h.conn)), nil
}

func setupTestUpgradeConns(t *testing.T) (clientSide net.Conn, serverSide net.Conn, backendClient net.Conn, backendServer net.Conn) {
	clientSide, serverSide = net.Pipe()
	backendClient, backendServer = net.Pipe()
	return clientSide, serverSide, backendClient, backendServer
}

func TestStreamTimeout_ActiveConnection(t *testing.T) {
	clientSide, serverSide, backendClient, backendServer := setupTestUpgradeConns(t)
	defer clientSide.Close()
	defer backendClient.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backendServer,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           serverSide,
		r:              bufio.NewReader(serverSide),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	// Echo goroutine on backend side
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := backendClient.Read(buf)
			if err != nil {
				return
			}
			_, _ = backendClient.Write(buf[:n])
		}
	}()

	// Send periodic data every 50ms for 300ms (total time 300ms > StreamTimeout 150ms)
	start := time.Now()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	buf := make([]byte, 1024)
	count := 0
	for count < 6 {
		<-ticker.C
		count++
		msg := []byte("ping")
		if _, err := clientSide.Write(msg); err != nil {
			t.Fatalf("failed to write message on iteration %d: %v", count, err)
		}
		_ = clientSide.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := clientSide.Read(buf)
		if err != nil {
			t.Fatalf("failed to read response on iteration %d: %v", count, err)
		}
		if string(buf[:n]) != "ping" {
			t.Fatalf("unexpected message: got %q, want %q", buf[:n], "ping")
		}
	}

	// Verify that the connection stayed open for the full 300ms active period
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Fatalf("active connection closed prematurely after %v", elapsed)
	}

	// Now stop sending data and wait for StreamTimeout (150ms) to trigger connection closure
	select {
	case <-done:
		// Connection timed out as expected after inactivity
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("connection did not time out after inactivity")
	}
}

func TestStreamTimeout_IdleConnection(t *testing.T) {
	clientSide, serverSide, backendClient, backendServer := setupTestUpgradeConns(t)
	defer clientSide.Close()
	defer backendClient.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backendServer,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           serverSide,
		r:              bufio.NewReader(serverSide),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	start := time.Now()
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < 80*time.Millisecond || elapsed > 300*time.Millisecond {
			t.Fatalf("idle connection closed at unexpected time: %v", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("idle connection did not time out within expected duration")
	}
}

func TestStreamTimeout_ImmediateErrorCleanup(t *testing.T) {
	clientSide, serverSide, backendClient, backendServer := setupTestUpgradeConns(t)

	h := &Handler{
		StreamTimeout: caddy.Duration(5 * time.Second), // Long timeout
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backendServer,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           serverSide,
		r:              bufio.NewReader(serverSide),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	start := time.Now()
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	// Immediately close clientSide to simulate connection error/disconnect
	clientSide.Close()
	backendClient.Close()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			t.Fatalf("connection error cleanup took too long: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("connection error did not trigger immediate cleanup")
	}
}
