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
	var resCh = make(chan streamResult, 1)
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
	go copier.copyToBackend(resCh)
	wg.Wait()

	if res := <-resCh; res.err != nil {
		t.Fatalf("copyToBackend() error = %v", res.err)
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

type halfClosePipeConn struct {
	r                io.ReadCloser
	w                io.WriteCloser
	closeWriteCalled atomic.Bool
}

func (h *halfClosePipeConn) Read(p []byte) (int, error) {
	return h.r.Read(p)
}

func (h *halfClosePipeConn) Write(p []byte) (int, error) {
	return h.w.Write(p)
}

func (h *halfClosePipeConn) Close() error {
	err1 := h.r.Close()
	err2 := h.w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (h *halfClosePipeConn) CloseWrite() error {
	h.closeWriteCalled.Store(true)
	return h.w.Close()
}

func (h *halfClosePipeConn) LocalAddr() net.Addr                { return nil }
func (h *halfClosePipeConn) RemoteAddr() net.Addr               { return nil }
func (h *halfClosePipeConn) SetDeadline(t time.Time) error      { return nil }
func (h *halfClosePipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (h *halfClosePipeConn) SetWriteDeadline(t time.Time) error { return nil }

func newHalfClosePipePair() (clientConn, clientProxyConn, backendProxyConn, backendConn *halfClosePipeConn) {
	rA, wA := net.Pipe()
	rB, wB := net.Pipe()
	rC, wC := net.Pipe()
	rD, wD := net.Pipe()

	clientConn = &halfClosePipeConn{r: rD, w: wA}
	clientProxyConn = &halfClosePipeConn{r: rA, w: wD}
	backendProxyConn = &halfClosePipeConn{r: rC, w: wB}
	backendConn = &halfClosePipeConn{r: rB, w: wC}

	return
}

type fakeHijacker struct {
	http.ResponseWriter
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (f *fakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.conn, f.brw, nil
}

func TestHandleUpgradeResponse_DualCopierHalfClose(t *testing.T) {
	clientConn, clientProxyConn, backendProxyConn, backendConn := newHalfClosePipePair()

	rec := httptest.NewRecorder()
	rw := &fakeHijacker{
		ResponseWriter: rec,
		conn:           clientProxyConn,
		brw:            bufio.NewReadWriter(bufio.NewReaderSize(clientProxyConn, 1), bufio.NewWriterSize(clientProxyConn, 1)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backendProxyConn,
	}

	h := Handler{
		logger:        caddy.Log(),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// 1. Client sends message and half-closes write side
	clientMsg := "hello from client"
	go func() {
		_, _ = clientConn.Write([]byte(clientMsg))
		_ = clientConn.CloseWrite()
	}()

	// 2. Backend reads message and expects EOF
	buf, err := io.ReadAll(backendConn)
	if err != nil {
		t.Fatalf("backend ReadAll error: %v", err)
	}
	if string(buf) != clientMsg {
		t.Fatalf("backend read %q, want %q", string(buf), clientMsg)
	}

	// 3. Backend sends response and half-closes write side
	backendMsg := "hello from backend"
	go func() {
		_, _ = backendConn.Write([]byte(backendMsg))
		_ = backendConn.CloseWrite()
	}()

	// 4. Client reads backend response and expects EOF
	bufClient, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client ReadAll error: %v", err)
	}
	if string(bufClient) != backendMsg {
		t.Fatalf("client read %q, want %q", string(bufClient), backendMsg)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleUpgradeResponse to complete")
	}

	if !clientProxyConn.closeWriteCalled.Load() {
		t.Errorf("expected CloseWrite to be called on clientProxyConn")
	}
	if !backendProxyConn.closeWriteCalled.Load() {
		t.Errorf("expected CloseWrite to be called on backendProxyConn")
	}
}

func TestHandleUpgradeResponse_ErrorTeardown(t *testing.T) {
	clientConn, clientProxyConn, backendProxyConn, backendConn := newHalfClosePipePair()

	rec := httptest.NewRecorder()
	rw := &fakeHijacker{
		ResponseWriter: rec,
		conn:           clientProxyConn,
		brw:            bufio.NewReadWriter(bufio.NewReaderSize(clientProxyConn, 1), bufio.NewWriterSize(clientProxyConn, 1)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backendProxyConn,
	}

	h := Handler{
		logger:        caddy.Log(),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Cause error by closing clientProxyConn
	_ = clientProxyConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleUpgradeResponse error teardown")
	}

	_ = clientConn.Close()
	_ = backendConn.Close()
}

func TestHandleUpgradeResponse_ContextCancel(t *testing.T) {
	clientConn, clientProxyConn, backendProxyConn, backendConn := newHalfClosePipePair()

	rec := httptest.NewRecorder()
	rw := &fakeHijacker{
		ResponseWriter: rec,
		conn:           clientProxyConn,
		brw:            bufio.NewReadWriter(bufio.NewReaderSize(clientProxyConn, 1), bufio.NewWriterSize(clientProxyConn, 1)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backendProxyConn,
	}

	h := Handler{
		logger:        caddy.Log(),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleUpgradeResponse context cancellation teardown")
	}

	_ = clientConn.Close()
	_ = backendConn.Close()
}

func TestHandleUpgradeResponse_StreamTimeout(t *testing.T) {
	clientConn, clientProxyConn, backendProxyConn, backendConn := newHalfClosePipePair()

	rec := httptest.NewRecorder()
	rw := &fakeHijacker{
		ResponseWriter: rec,
		conn:           clientProxyConn,
		brw:            bufio.NewReadWriter(bufio.NewReaderSize(clientProxyConn, 1), bufio.NewWriterSize(clientProxyConn, 1)),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}},
		Body:       backendProxyConn,
	}

	h := Handler{
		logger:        caddy.Log(),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
	}
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleUpgradeResponse stream timeout teardown")
	}

	_ = clientConn.Close()
	_ = backendConn.Close()
}
