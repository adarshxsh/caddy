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

func TestActivityRWC(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	activityChan := make(chan struct{}, 1)
	arwc := activityRWC{
		ReadWriteCloser: c1,
		activityChan:    activityChan,
	}

	// Test Write triggers activity
	go func() {
		buf := make([]byte, 5)
		c2.Read(buf)
	}()
	_, err := arwc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	select {
	case <-activityChan:
		// success
	default:
		t.Fatal("expected activity channel signal after Write")
	}

	// Test Read triggers activity
	go func() {
		c2.Write([]byte("world"))
	}()

	buf := make([]byte, 5)
	_, err = arwc.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	select {
	case <-activityChan:
		// success
	default:
		t.Fatal("expected activity channel signal after Read")
	}
}

type hijackableRecorder struct {
	http.ResponseWriter
	conn net.Conn
	rwc  *bufio.ReadWriter
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rwc, nil
}

func TestStreamTimeoutWithActivity(t *testing.T) {
	clientConn, userConn := net.Pipe()
	backendConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer backendConn.Close()

	rec := &hijackableRecorder{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userConn,
		rwc:            bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       serverConn,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rec, req, res)
		close(done)
	}()

	// Perform periodic activity every 50ms for 300ms total (> 150ms StreamTimeout)
	for i := 0; i < 6; i++ {
		time.Sleep(50 * time.Millisecond)

		select {
		case <-done:
			t.Fatalf("connection timed out prematurely at iteration %d", i)
		default:
		}

		// Send data from client to backend
		if _, err := clientConn.Write([]byte("ping")); err != nil {
			t.Fatalf("client write failed at iteration %d: %v", i, err)
		}

		buf := make([]byte, 4)
		if _, err := backendConn.Read(buf); err != nil {
			t.Fatalf("backend read failed at iteration %d: %v", i, err)
		}
	}

	// Now cease all activity and wait for timeout (> 150ms)
	select {
	case <-done:
		// success: timed out after activity stopped
	case <-time.After(500 * time.Millisecond):
		t.Fatal("connection failed to time out after inactivity")
	}
}

func TestStreamTimeoutInactive(t *testing.T) {
	_, userConn := net.Pipe()
	_, serverConn := net.Pipe()

	rec := &hijackableRecorder{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userConn,
		rwc:            bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: 101,
		Header:     make(http.Header),
		Body:       serverConn,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	start := time.Now()
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rec, req, res)
		close(done)
	}()

	select {
	case <-done:
		if duration := time.Since(start); duration < 80*time.Millisecond {
			t.Fatalf("connection closed too quickly: %v", duration)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("inactive stream failed to time out")
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
