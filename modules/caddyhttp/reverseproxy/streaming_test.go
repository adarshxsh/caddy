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
	"sync/atomic"
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

func TestActivityRWC(t *testing.T) {
	activityChan := make(chan struct{}, 1)
	lastActivity := new(atomic.Int64)

	var buf bytes.Buffer
	base := nopReadWriteCloser{Reader: strings.NewReader("hello"), Writer: &buf}
	arwc := &activityRWC{
		ReadWriteCloser: base,
		activityChan:    activityChan,
		lastActivity:    lastActivity,
	}

	if arwc.Unwrap() != base {
		t.Fatalf("Unwrap returned unexpected reader/writer")
	}

	t0 := time.Now().UnixNano()
	p := make([]byte, 10)
	n, err := arwc.Read(p)
	if err != nil || n != 5 {
		t.Fatalf("Read failed: n=%d err=%v", n, err)
	}

	if lastActivity.Load() < t0 {
		t.Fatalf("lastActivity was not updated after Read")
	}

	select {
	case <-activityChan:
	default:
		t.Fatalf("activityChan was not signaled after Read")
	}

	t1 := time.Now().UnixNano()
	n, err = arwc.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}

	if lastActivity.Load() < t1 {
		t.Fatalf("lastActivity was not updated after Write")
	}

	select {
	case <-activityChan:
	default:
		t.Fatalf("activityChan was not signaled after Write")
	}
}

type mockHijackRW struct {
	http.ResponseWriter
	conn net.Conn
}

func (m *mockHijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn)), nil
}

func TestStreamTimeoutActivityReset(t *testing.T) {
	clientConn, frontConn := net.Pipe()
	backConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer backConn.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req = req.WithContext(context.Background())

	res := &http.Response{
		StatusCode: 101,
		Header:     http.Header{},
		Body:       backendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &mockHijackRW{ResponseWriter: httptest.NewRecorder(), conn: frontConn}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	// Send periodic traffic for 350ms (well past initial 150ms timeout)
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	stopTimer := time.NewTimer(350 * time.Millisecond)
	defer stopTimer.Stop()

	buf := make([]byte, 32)
Loop:
	for {
		select {
		case <-stopTimer.C:
			break Loop
		case <-ticker.C:
			_, writeErr := clientConn.Write([]byte("data"))
			if writeErr != nil {
				t.Fatalf("client write failed: %v", writeErr)
			}
			n, readErr := backConn.Read(buf)
			if readErr != nil {
				t.Fatalf("backend read failed: %v", readErr)
			}
			if string(buf[:n]) != "data" {
				t.Fatalf("unexpected read data: %s", string(buf[:n]))
			}
		case <-done:
			t.Fatalf("stream timed out prematurely during active data transfer")
		}
	}

	// Traffic stopped. Verify that stream times out and closes after inactivity duration (~150ms)
	select {
	case <-done:
		// Passed - stream closed after inactivity
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("stream failed to close after inactivity timeout")
	}
}

func TestStreamTimeoutIdleClosure(t *testing.T) {
	clientConn, frontConn := net.Pipe()
	backConn, backendConn := net.Pipe()

	defer clientConn.Close()
	defer backConn.Close()

	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req = req.WithContext(context.Background())

	res := &http.Response{
		StatusCode: 101,
		Header:     http.Header{},
		Body:       backendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &mockHijackRW{ResponseWriter: httptest.NewRecorder(), conn: frontConn}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
		// Passed - stream closed due to idle timeout
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("idle stream failed to close automatically after timeout duration")
	}
}
