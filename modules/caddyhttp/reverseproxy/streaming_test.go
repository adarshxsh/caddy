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

type hijackableResponseWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, brw, nil
}

type deadlineTrackerConn struct {
	net.Conn
	mu              sync.Mutex
	deadlineCleared bool
}

func (c *deadlineTrackerConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	if t.IsZero() {
		c.deadlineCleared = true
	}
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineTrackerConn) isDeadlineCleared() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineCleared
}

func TestHandleUpgradeResponse_ClearsDeadline(t *testing.T) {
	clientConn, clientServerConn := net.Pipe()
	defer clientConn.Close()
	defer clientServerConn.Close()

	backendConn, backendServerConn := net.Pipe()
	defer backendConn.Close()
	defer backendServerConn.Close()

	tracker := &deadlineTrackerConn{Conn: backendConn}

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: tracker,
	}

	rw := &hijackableResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientServerConn,
	}

	var wg sync.WaitGroup

	// Run handleUpgradeResponse in goroutine since it will block until connections close
	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
	}()

	// Give handleUpgradeResponse a moment to process the upgrade response and clear deadlines
	time.Sleep(50 * time.Millisecond)

	if !tracker.isDeadlineCleared() {
		t.Errorf("expected SetDeadline(zero) to be called on backend connection")
	}

	// Close connections to unblock streaming copier
	clientConn.Close()
	backendServerConn.Close()
}
