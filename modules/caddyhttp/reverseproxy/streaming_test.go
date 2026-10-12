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

func TestActivityRWC(t *testing.T) {
	activityCount := 0
	onActivity := func() {
		activityCount++
	}

	buf := bytes.NewBuffer([]byte("hello"))
	rwc := &activityRWC{
		ReadWriteCloser: nopReadWriteCloser{Reader: buf, Writer: io.Discard},
		onActivity:      onActivity,
	}

	readBuf := make([]byte, 10)
	n, err := rwc.Read(readBuf)
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes read, got %d, err %v", n, err)
	}
	if activityCount != 1 {
		t.Fatalf("expected activityCount 1, got %d", activityCount)
	}

	// Read when empty (n == 0)
	n, _ = rwc.Read(readBuf)
	if n != 0 {
		t.Fatalf("expected 0 bytes read, got %d", n)
	}
	if activityCount != 1 {
		t.Fatalf("expected activityCount 1 after 0-byte read, got %d", activityCount)
	}

	// Write non-zero
	n, err = rwc.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes written, got %d, err %v", n, err)
	}
	if activityCount != 2 {
		t.Fatalf("expected activityCount 2 after write, got %d", activityCount)
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func newHijackRecorder(conn net.Conn) *hijackRecorder {
	return &hijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             conn,
	}
}

func (r *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(r.conn), bufio.NewWriter(r.conn))
	return r.conn, brw, nil
}

func TestStreamIdleTimeoutReset(t *testing.T) {
	clientUser, serverUser := net.Pipe()
	clientBackend, serverBackend := net.Pipe()

	defer clientUser.Close()
	defer serverUser.Close()
	defer clientBackend.Close()
	defer serverBackend.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	recorder := newHijackRecorder(serverUser)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: serverBackend,
	}

	var wg sync.WaitGroup
	start := time.Now()

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, recorder, req, res)
		wg.Wait()
		close(done)
	}()

	// Send data periodically every 50ms for 350ms total (> 150ms StreamTimeout).
	// Since data flows every 50ms, stream should NOT time out during this period.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	sendCount := 0

	for sendCount < 7 {
		<-ticker.C
		_, err := clientUser.Write([]byte("ping"))
		if err != nil {
			t.Fatalf("failed to write data: %v", err)
		}
		buf := make([]byte, 10)
		_, err = clientBackend.Read(buf)
		if err != nil {
			t.Fatalf("failed to read data on backend: %v", err)
		}
		sendCount++
	}

	// Ensure that after 350ms of periodic traffic, the connection is still open
	select {
	case <-done:
		t.Fatalf("stream closed prematurely after %v while active", time.Since(start))
	default:
	}

	// Now stop sending data and wait for inactivity timeout (150ms)
	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < 450*time.Millisecond {
			t.Fatalf("stream closed too early: %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("stream failed to close on idle timeout")
	}
}

func TestStreamIdleTimeout_Inactive(t *testing.T) {
	clientUser, serverUser := net.Pipe()
	clientBackend, serverBackend := net.Pipe()

	defer clientUser.Close()
	defer serverUser.Close()
	defer clientBackend.Close()
	defer serverBackend.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	recorder := newHijackRecorder(serverUser)
	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: serverBackend,
	}

	var wg sync.WaitGroup
	start := time.Now()

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, recorder, req, res)
		wg.Wait()
		close(done)
	}()

	// Zero traffic sent, stream should close automatically after StreamTimeout (100ms)
	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < 80*time.Millisecond || elapsed > 300*time.Millisecond {
			t.Fatalf("expected close around 100ms, got %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("inactive stream failed to close on idle timeout")
	}
}
