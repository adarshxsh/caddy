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

	"go.uber.org/zap"

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

type testHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (h *testHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, nil
}

func TestDualConnectionTeardownContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	clientProxy, clientUser := net.Pipe()
	backendProxy, backendUser := net.Pipe()

	defer clientUser.Close()
	defer backendUser.Close()

	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backendProxy,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	h := Handler{
		logger: zap.NewNop(),
	}

	rw := &testHijacker{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientProxy,
		rw:               bufio.NewReadWriter(bufio.NewReader(clientProxy), bufio.NewWriter(clientProxy)),
	}

	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Cancel the context.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out after context cancellation")
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() timed out after context cancellation")
	}

	// Verify both client and backend socket connections were closed.
	buf := make([]byte, 10)
	_, err1 := clientUser.Read(buf)
	if err1 == nil {
		t.Errorf("expected clientUser to be closed, but Read succeeded")
	}

	_, err2 := backendUser.Read(buf)
	if err2 == nil {
		t.Errorf("expected backendUser to be closed, but Read succeeded")
	}
}

func TestDualConnectionTeardownCopierError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientProxy, clientUser := net.Pipe()
	backendProxy, backendUser := net.Pipe()

	defer clientUser.Close()
	defer backendUser.Close()

	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       backendProxy,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	h := Handler{
		logger: zap.NewNop(),
	}

	rw := &testHijacker{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientProxy,
		rw:               bufio.NewReadWriter(bufio.NewReader(clientProxy), bufio.NewWriter(clientProxy)),
	}

	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Cause an error on backend side by closing backendUser.
	backendUser.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out after copier error")
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() timed out after copier error")
	}

	// Cross-cancellation: client side must also be closed.
	buf := make([]byte, 10)
	_, err := clientUser.Read(buf)
	if err == nil {
		t.Errorf("expected clientUser to be closed via cross-cancellation, but Read succeeded")
	}
}

func TestDualConnectionTeardownExtendedConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientProxy, clientUser := net.Pipe()
	backendProxy, backendUser := net.Pipe()

	defer clientUser.Close()
	defer backendUser.Close()

	varMap := make(map[string]any)
	reqCtx := context.WithValue(ctx, caddyhttp.VarsCtxKey, varMap)
	caddyhttp.SetVar(reqCtx, "extended_connect_websocket_body", clientProxy)
	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(reqCtx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       backendProxy,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	h := Handler{
		logger: zap.NewNop(),
	}

	recorder := httptest.NewRecorder()
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, recorder, req, res)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Cancel context to test H2 extended connect context cancellation teardown.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse timed out on extended connect context cancellation")
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() timed out on extended connect context cancellation")
	}
}
