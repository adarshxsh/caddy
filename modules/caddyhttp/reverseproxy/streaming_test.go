package reverseproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

func TestSwitchProtocolCopierBidirectionalClosure(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := &switchProtocolCopier{
		user:    s1,
		backend: s2,
		wg:      &wg,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	// Close client 1 side to simulate disconnection / stream teardown
	_ = c1.Close()

	// Wait for wg with timeout to ensure both copier routines unblock and complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: both copiers finished
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for copier goroutines to terminate after one side closed")
	}

	_ = c2.Close()
}

type deadlineTrackerConn struct {
	net.Conn
	mu            sync.Mutex
	writeDeadline time.Time
}

func (d *deadlineTrackerConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.writeDeadline = t
	d.mu.Unlock()
	return d.Conn.SetWriteDeadline(t)
}

func TestWriteDeadlineWriterSetsDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tracker := &deadlineTrackerConn{Conn: c1}
	dw := writeDeadlineWriter{
		w:            tracker,
		writeTimeout: 500 * time.Millisecond,
	}

	go func() {
		buf := make([]byte, 10)
		_, _ = c2.Read(buf)
	}()

	start := time.Now()
	n, err := dw.Write([]byte("test"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 4 {
		t.Fatalf("wrote %d bytes, expected 4", n)
	}

	tracker.mu.Lock()
	deadline := tracker.writeDeadline
	tracker.mu.Unlock()

	if deadline.IsZero() {
		t.Fatal("expected write deadline to be set, got zero time")
	}
	if deadline.Before(start.Add(400 * time.Millisecond)) {
		t.Fatalf("write deadline %v set too early relative to start %v", deadline, start)
	}
}

func TestSwitchProtocolCopierWriteDeadlineExceeded(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := &switchProtocolCopier{
		user:         s1,
		backend:      s2,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	// Write data to c1 (user side) which will copy to s2 (backend side).
	// But no one reads from c2 (backend side end), so write to s2 will block and hit write deadline!
	go func() {
		_, _ = c1.Write([]byte("data that will stall writing to backend"))
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: write deadline expired and unblocked both copiers
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for copier routines to terminate after write deadline")
	}
}

func TestCaddyfileStreamWriteTimeout(t *testing.T) {
	input := `reverse_proxy {
		stream_write_timeout 10s
	}`
	d := caddyfile.NewTestDispenser(input)
	h := &Handler{}
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error parsing stream_write_timeout: %v", err)
	}
	if h.StreamWriteTimeout != caddy.Duration(10*time.Second) {
		t.Fatalf("expected StreamWriteTimeout 10s, got %v", h.StreamWriteTimeout)
	}
}

type mockResponseWriter struct {
	*httptest.ResponseRecorder
	writeDeadline time.Time
	readDeadline  time.Time
	closed        bool
}

func (m *mockResponseWriter) SetWriteDeadline(t time.Time) error {
	m.writeDeadline = t
	return nil
}

func (m *mockResponseWriter) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockResponseWriter) Close() error {
	m.closed = true
	return nil
}

type mockBody struct {
	io.Reader
	closed       bool
	readDeadline time.Time
}

func (m *mockBody) Close() error {
	m.closed = true
	return nil
}

func (m *mockBody) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func TestH2ReadWriteCloser(t *testing.T) {
	body := &mockBody{Reader: strings.NewReader("test")}
	rec := httptest.NewRecorder()
	mrw := &mockResponseWriter{ResponseRecorder: rec}

	rwc := h2ReadWriteCloser{
		ReadCloser:     body,
		ResponseWriter: mrw,
	}

	// Test SetWriteDeadline
	now := time.Now()
	if err := rwc.SetWriteDeadline(now); err != nil {
		t.Fatalf("SetWriteDeadline failed: %v", err)
	}
	if !mrw.writeDeadline.Equal(now) {
		t.Errorf("writeDeadline = %v, want %v", mrw.writeDeadline, now)
	}

	// Test SetReadDeadline
	if err := rwc.SetReadDeadline(now); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if !body.readDeadline.Equal(now) {
		t.Errorf("readDeadline = %v, want %v", body.readDeadline, now)
	}

	// Test SetDeadline
	later := now.Add(time.Second)
	if err := rwc.SetDeadline(later); err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}
	if !mrw.writeDeadline.Equal(later) {
		t.Errorf("writeDeadline = %v, want %v", mrw.writeDeadline, later)
	}
	if !body.readDeadline.Equal(later) {
		t.Errorf("readDeadline = %v, want %v", body.readDeadline, later)
	}

	// Test Close
	if err := rwc.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !body.closed {
		t.Errorf("body not closed")
	}
	if !mrw.closed {
		t.Errorf("response writer not closed")
	}
}

func TestHandleUpgradeResponseContextCancellation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	backendClient, backendServer := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()
	defer backendClient.Close()
	defer backendServer.Close()

	h := &Handler{}
	var wg sync.WaitGroup

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rec := httptest.NewRecorder()

	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), rec, &caddyhttp.Server{})
	caddyhttp.SetVar(req.Context(), "extended_connect_websocket_body", clientConn)

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       backendServer,
	}

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rec, req, res)
		wg.Wait()
		close(done)
	}()

	// Cancel context to trigger stream cancellation
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success: wg.Wait() unblocked upon context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse/wg.Wait timed out on context cancellation; goroutine leaked")
	}
}

