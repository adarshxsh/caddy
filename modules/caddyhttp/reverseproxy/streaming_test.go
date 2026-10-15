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

func TestHandleUpgradeResponseTeardownDeadlines(t *testing.T) {
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

	// Simulate client writing something to serverConn then closing write side
	go func() {
		_, _ = serverConn.Write([]byte("ping"))
		_ = serverConn.Close()
	}()

	select {
	case <-done:
		// Success: wg.Wait() completed within reasonable time without hanging
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse/wg.Wait timed out on teardown; goroutine leaked")
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
