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

type testPipeConn struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	cw        func() error
	closeOnce sync.Once
}

func (c *testPipeConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *testPipeConn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c *testPipeConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.r.Close()
		_ = c.w.Close()
	})
	return nil
}

func (c *testPipeConn) CloseWrite() error {
	if c.cw != nil {
		return c.cw()
	}
	return c.w.Close()
}

func (c *testPipeConn) LocalAddr() net.Addr                { return nil }
func (c *testPipeConn) RemoteAddr() net.Addr               { return nil }
func (c *testPipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *testPipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testPipeConn) SetWriteDeadline(t time.Time) error { return nil }

type mockHijackRW struct {
	header http.Header
	conn   net.Conn
	brw    *bufio.ReadWriter
}

func (m *mockHijackRW) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mockHijackRW) WriteHeader(statusCode int) {}

func (m *mockHijackRW) Write(b []byte) (int, error) {
	return m.conn.Write(b)
}

func (m *mockHijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

func createTestPair() (clientEnd *testPipeConn, userConn *testPipeConn, backConn *testPipeConn, backendEnd *testPipeConn) {
	c2pReader, c2pWriter := io.Pipe()
	p2cReader, p2cWriter := io.Pipe()

	p2bReader, p2bWriter := io.Pipe()
	b2pReader, b2pWriter := io.Pipe()

	clientEnd = &testPipeConn{
		r:  p2cReader,
		w:  c2pWriter,
		cw: func() error { return c2pWriter.Close() },
	}
	userConn = &testPipeConn{
		r:  c2pReader,
		w:  p2cWriter,
		cw: func() error { return p2cWriter.Close() },
	}

	backConn = &testPipeConn{
		r:  b2pReader,
		w:  p2bWriter,
		cw: func() error { return p2bWriter.Close() },
	}
	backendEnd = &testPipeConn{
		r:  p2bReader,
		w:  b2pWriter,
		cw: func() error { return b2pWriter.Close() },
	}

	return clientEnd, userConn, backConn, backendEnd
}

func TestHandleUpgradeResponse_ClientHalfClose(t *testing.T) {
	clientEnd, userConn, backConn, backendEnd := createTestPair()

	rw := &mockHijackRW{
		conn: userConn,
		brw:  bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backConn,
	}

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	// 1. Client sends message and half-closes write side
	msg1 := []byte("hello backend")
	if _, err := clientEnd.Write(msg1); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	buf := make([]byte, 100)
	n, err := backendEnd.Read(buf)
	if err != nil || string(buf[:n]) != "hello backend" {
		t.Fatalf("backend read failed: %v, got %q", err, string(buf[:n]))
	}

	// Client half-closes send stream
	if err := clientEnd.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite failed: %v", err)
	}

	// Backend reads EOF on its request stream
	n, err = backendEnd.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF on backend read, got %v (n=%d)", err, n)
	}

	// Verify handleUpgradeResponse has NOT returned yet
	select {
	case <-done:
		t.Fatal("handleUpgradeResponse returned prematurely after client half-close")
	default:
	}

	// 2. Backend sends response message and closes write side
	msg2 := []byte("hello client response")
	if _, err := backendEnd.Write(msg2); err != nil {
		t.Fatalf("backend write failed: %v", err)
	}

	n, err = clientEnd.Read(buf)
	if err != nil || string(buf[:n]) != "hello client response" {
		t.Fatalf("client read failed: %v, got %q", err, string(buf[:n]))
	}

	if err := backendEnd.CloseWrite(); err != nil {
		t.Fatalf("backend CloseWrite failed: %v", err)
	}

	// Client receives EOF
	n, err = clientEnd.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF on client read, got %v (n=%d)", err, n)
	}

	// Wait for handleUpgradeResponse to complete cleanly
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for dual-stream completion")
	}

	wg.Wait()
}

func TestHandleUpgradeResponse_ServerHalfClose(t *testing.T) {
	clientEnd, userConn, backConn, backendEnd := createTestPair()

	rw := &mockHijackRW{
		conn: userConn,
		brw:  bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backConn,
	}

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	// 1. Backend sends message and half-closes response stream
	msg1 := []byte("welcome from backend")
	if _, err := backendEnd.Write(msg1); err != nil {
		t.Fatalf("backend write failed: %v", err)
	}

	buf := make([]byte, 100)
	n, err := clientEnd.Read(buf)
	if err != nil || string(buf[:n]) != "welcome from backend" {
		t.Fatalf("client read failed: %v, got %q", err, string(buf[:n]))
	}

	if err := backendEnd.CloseWrite(); err != nil {
		t.Fatalf("backend CloseWrite failed: %v", err)
	}

	n, err = clientEnd.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF on client read, got %v (n=%d)", err, n)
	}

	// Verify handleUpgradeResponse has NOT returned yet
	select {
	case <-done:
		t.Fatal("handleUpgradeResponse returned prematurely after server half-close")
	default:
	}

	// 2. Client sends final frame to backend and half-closes
	msg2 := []byte("final request frame")
	if _, err := clientEnd.Write(msg2); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	n, err = backendEnd.Read(buf)
	if err != nil || string(buf[:n]) != "final request frame" {
		t.Fatalf("backend read failed: %v, got %q", err, string(buf[:n]))
	}

	if err := clientEnd.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite failed: %v", err)
	}

	n, err = backendEnd.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF on backend read, got %v (n=%d)", err, n)
	}

	// Wait for handleUpgradeResponse to complete cleanly
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out waiting for completion")
	}

	wg.Wait()
}

func TestHandleUpgradeResponse_ContextCanceled(t *testing.T) {
	_, userConn, backConn, _ := createTestPair()

	rw := &mockHijackRW{
		conn: userConn,
		brw:  bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backConn,
	}

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse failed to exit on context cancellation")
	}

	wg.Wait()
}

func TestHandleUpgradeResponse_StreamTimeout(t *testing.T) {
	_, userConn, backConn, _ := createTestPair()

	rw := &mockHijackRW{
		conn: userConn,
		brw:  bufio.NewReadWriter(bufio.NewReader(userConn), bufio.NewWriter(userConn)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backConn,
	}

	handler := &Handler{
		connectionsMu: new(sync.Mutex),
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse failed to exit on stream timeout")
	}

	wg.Wait()
}
