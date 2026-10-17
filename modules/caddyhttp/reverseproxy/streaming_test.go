package reverseproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
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

type pipeConn struct {
	r          *io.PipeReader
	w          *io.PipeWriter
	closeWrite atomic.Bool
	closed     atomic.Bool
	onClose    func()
}

func newPipePair() (caddyConn *pipeConn, peerConn *pipeConn) {
	r1, w1 := io.Pipe() // peer -> caddy
	r2, w2 := io.Pipe() // caddy -> peer

	caddyConn = &pipeConn{r: r1, w: w2}
	peerConn = &pipeConn{r: r2, w: w1}
	return caddyConn, peerConn
}

func (p *pipeConn) Read(b []byte) (int, error) {
	if p.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return p.r.Read(b)
}

func (p *pipeConn) Write(b []byte) (int, error) {
	if p.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return p.w.Write(b)
}

func (p *pipeConn) CloseWrite() error {
	p.closeWrite.Store(true)
	return p.w.Close()
}

func (p *pipeConn) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		_ = p.r.Close()
		_ = p.w.Close()
		if p.onClose != nil {
			p.onClose()
		}
	}
	return nil
}

type mockHijackResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

type nopConn struct {
	*pipeConn
}

func (n nopConn) LocalAddr() net.Addr  { return nil }
func (n nopConn) RemoteAddr() net.Addr { return nil }
func (n nopConn) SetDeadline(t time.Time) error      { return nil }
func (n nopConn) SetReadDeadline(t time.Time) error  { return nil }
func (n nopConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHandleUpgradeResponse_ClientEOFFirst(t *testing.T) {
	caddyClientConn, clientPeerConn := newPipePair()
	caddyBackendConn, backendPeerConn := newPipePair()

	var wg sync.WaitGroup
	h := &Handler{}
	logger := zap.NewNop()

	rw := &mockHijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           nopConn{caddyClientConn},
		brw:            bufio.NewReadWriter(bufio.NewReader(caddyClientConn), bufio.NewWriter(caddyClientConn)),
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       caddyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// 1. Client sends request data then half-closes.
	_, err := clientPeerConn.Write([]byte("hello backend"))
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}
	_ = clientPeerConn.CloseWrite()

	// 2. Backend reads request data and verifies EOF on backend reader.
	buf := make([]byte, 64)
	n, err := backendPeerConn.Read(buf)
	if err != nil || string(buf[:n]) != "hello backend" {
		t.Fatalf("backend read got %q, err %v", string(buf[:n]), err)
	}
	n, err = backendPeerConn.Read(buf)
	if err != io.EOF {
		t.Fatalf("backend expected EOF, got n=%d, err=%v", n, err)
	}

	if !caddyBackendConn.closeWrite.Load() {
		t.Fatalf("expected CloseWrite to be called on caddyBackendConn")
	}

	// 3. Backend continues sending response data while client write stream is closed.
	_, err = backendPeerConn.Write([]byte("response 1"))
	if err != nil {
		t.Fatalf("backend write 1 error: %v", err)
	}

	n, err = clientPeerConn.Read(buf)
	if err != nil || string(buf[:n]) != "response 1" {
		t.Fatalf("client read 1 got %q, err %v", string(buf[:n]), err)
	}

	_, err = backendPeerConn.Write([]byte("response 2"))
	if err != nil {
		t.Fatalf("backend write 2 error: %v", err)
	}

	_ = backendPeerConn.CloseWrite()

	n, err = clientPeerConn.Read(buf)
	if err != nil || string(buf[:n]) != "response 2" {
		t.Fatalf("client read 2 got %q, err %v", string(buf[:n]), err)
	}

	n, err = clientPeerConn.Read(buf)
	if err != io.EOF {
		t.Fatalf("client expected EOF, got n=%d, err=%v", n, err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handleUpgradeResponse timed out waiting for completion")
	}
}

func TestHandleUpgradeResponse_BackendEOFFirst(t *testing.T) {
	caddyClientConn, clientPeerConn := newPipePair()
	caddyBackendConn, backendPeerConn := newPipePair()

	var wg sync.WaitGroup
	h := &Handler{}
	logger := zap.NewNop()

	rw := &mockHijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           nopConn{caddyClientConn},
		brw:            bufio.NewReadWriter(bufio.NewReader(caddyClientConn), bufio.NewWriter(caddyClientConn)),
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       caddyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// 1. Backend sends data and half-closes write stream.
	_, err := backendPeerConn.Write([]byte("backend payload"))
	if err != nil {
		t.Fatalf("backend write error: %v", err)
	}
	_ = backendPeerConn.CloseWrite()

	// 2. Client reads backend data and receives EOF.
	buf := make([]byte, 64)
	n, err := clientPeerConn.Read(buf)
	if err != nil || string(buf[:n]) != "backend payload" {
		t.Fatalf("client read got %q, err %v", string(buf[:n]), err)
	}
	n, err = clientPeerConn.Read(buf)
	if err != io.EOF {
		t.Fatalf("client expected EOF, got n=%d, err=%v", n, err)
	}

	if !caddyClientConn.closeWrite.Load() {
		t.Fatalf("expected CloseWrite to be called on caddyClientConn")
	}

	// 3. Client continues writing data to backend.
	_, err = clientPeerConn.Write([]byte("remaining client data"))
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}
	_ = clientPeerConn.CloseWrite()

	n, err = backendPeerConn.Read(buf)
	if err != nil || string(buf[:n]) != "remaining client data" {
		t.Fatalf("backend read got %q, err %v", string(buf[:n]), err)
	}
	n, err = backendPeerConn.Read(buf)
	if err != io.EOF {
		t.Fatalf("backend expected EOF, got n=%d, err=%v", n, err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handleUpgradeResponse timed out waiting for completion")
	}
}

func TestHandleUpgradeResponse_NonEOFError(t *testing.T) {
	caddyClientConn, clientPeerConn := newPipePair()
	caddyBackendConn, backendPeerConn := newPipePair()

	var wg sync.WaitGroup
	h := &Handler{}
	logger := zap.NewNop()

	rw := &mockHijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           nopConn{caddyClientConn},
		brw:            bufio.NewReadWriter(bufio.NewReader(caddyClientConn), bufio.NewWriter(caddyClientConn)),
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       caddyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Inject non-EOF error on client reader.
	_ = caddyClientConn.r.CloseWithError(errors.New("connection reset"))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handleUpgradeResponse failed to tear down streams on non-EOF error")
	}

	_ = clientPeerConn
	_ = backendPeerConn
}

func TestHandleUpgradeResponse_StreamTimeout(t *testing.T) {
	caddyClientConn, clientPeerConn := newPipePair()
	caddyBackendConn, backendPeerConn := newPipePair()

	var wg sync.WaitGroup
	h := &Handler{
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
	}
	logger := zap.NewNop()

	rw := &mockHijackResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           nopConn{caddyClientConn},
		brw:            bufio.NewReadWriter(bufio.NewReader(caddyClientConn), bufio.NewWriter(caddyClientConn)),
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       caddyBackendConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handleUpgradeResponse failed to exit after stream timeout")
	}

	_ = clientPeerConn
	_ = backendPeerConn
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

