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

type mockHijackResponseWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	bufr := bufio.NewReader(m.conn)
	bufw := bufio.NewWriter(m.conn)
	return m.conn, bufio.NewReadWriter(bufr, bufw), nil
}

func TestStreamTimeout_ActiveConnection(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer backendConn.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	rw := &mockHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             proxyClientConn,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	// Perform periodic activity for 350ms (> 150ms StreamTimeout)
	stopActivity := make(chan struct{})
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		buf := make([]byte, 4)
		for {
			select {
			case <-stopActivity:
				return
			case <-ticker.C:
				go func() {
					clientConn.Write([]byte("ping"))
				}()
				backendConn.Read(buf)
			}
		}
	}()

	// Verify connection remains open during activity
	select {
	case <-done:
		t.Fatal("connection timed out prematurely despite active data transfer")
	case <-time.After(350 * time.Millisecond):
		// Connection correctly stayed open during active period
	}

	// Stop activity and verify it times out
	close(stopActivity)

	select {
	case <-done:
		// Connection timed out as expected after activity stopped
	case <-time.After(400 * time.Millisecond):
		t.Fatal("connection failed to time out after activity stopped")
	}
}

func TestStreamTimeout_IdleConnection(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer backendConn.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	rw := &mockHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             proxyClientConn,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

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
		if elapsed < 80*time.Millisecond {
			t.Fatalf("connection closed too early: %v", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("idle connection failed to time out")
	}
}

func TestStreamTimeout_ZeroTimeout(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackendConn, backendConn := net.Pipe()

	h := &Handler{
		StreamTimeout: 0,
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	rw := &mockHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             proxyClientConn,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       proxyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	// Verify connection does not time out after 150ms
	select {
	case <-done:
		t.Fatal("connection timed out when StreamTimeout was 0")
	case <-time.After(150 * time.Millisecond):
		// Expected: connection remains open
	}

	// Explicitly close client connection to clean up
	clientConn.Close()
	backendConn.Close()

	select {
	case <-done:
		// Clean exit after explicit close
	case <-time.After(200 * time.Millisecond):
		t.Fatal("connection failed to close after explicit close")
	}
}

