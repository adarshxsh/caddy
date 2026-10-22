package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
	"go.uber.org/zap"
)

func TestTcpRWTimeoutConn_ClearDeadlines(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(150 * time.Millisecond)
		conn.Write([]byte("pong"))
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	tc := &tcpRWTimeoutConn{
		TCPConn: clientConn.(*net.TCPConn),
	}
	tc.readTimeout.Store(int64(50 * time.Millisecond))
	tc.writeTimeout.Store(int64(50 * time.Millisecond))

	if err := tc.ClearDeadlines(); err != nil {
		t.Fatalf("ClearDeadlines failed: %v", err)
	}

	if rt := tc.readTimeout.Load(); rt != 0 {
		t.Fatalf("expected readTimeout to be 0, got %d", rt)
	}
	if wt := tc.writeTimeout.Load(); wt != 0 {
		t.Fatalf("expected writeTimeout to be 0, got %d", wt)
	}

	buf := make([]byte, 4)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error reading from connection after ClearDeadlines: %v", err)
	}
	if got := string(buf[:n]); got != "pong" {
		t.Fatalf("expected 'pong', got %q", got)
	}
	<-done
}

type mockUnwrapperNetConn struct {
	net.Conn
	target net.Conn
}

func (m mockUnwrapperNetConn) NetConn() net.Conn { return m.target }

type mockUnwrapperUnwrap struct {
	net.Conn
	target net.Conn
}

func (m mockUnwrapperUnwrap) Unwrap() net.Conn { return m.target }

func TestClearDeadlines_Unwrapping(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	dummyClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dummyClient.Close()

	tc := &tcpRWTimeoutConn{
		TCPConn: dummyClient.(*net.TCPConn),
	}
	tc.readTimeout.Store(int64(100 * time.Millisecond))
	tc.writeTimeout.Store(int64(100 * time.Millisecond))

	wrapped1 := mockUnwrapperNetConn{Conn: tc, target: tc}
	wrapped2 := mockUnwrapperUnwrap{Conn: wrapped1, target: wrapped1}

	if err := clearDeadlines(wrapped2); err != nil {
		t.Fatalf("clearDeadlines failed: %v", err)
	}

	if tc.readTimeout.Load() != 0 || tc.writeTimeout.Load() != 0 {
		t.Fatalf("clearDeadlines failed to traverse unwrapping layers and clear tcpRWTimeoutConn timeouts")
	}
}

type hijackableRecorder struct {
	*httptest.ResponseRecorder
	clientConn net.Conn
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	res := h.Result()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", res.StatusCode, http.StatusText(res.StatusCode))
	res.Header.Write(&buf)
	buf.WriteString("\r\n")
	_, _ = h.clientConn.Write(buf.Bytes())

	brw := bufio.NewReadWriter(bufio.NewReader(h.clientConn), bufio.NewWriter(h.clientConn))
	return h.clientConn, brw, nil
}

func TestIntegration_StandardHTTP_TimesOut(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("slow response"))
	}))
	defer backend.Close()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(80 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	upstreams := UpstreamPool{
		{Host: new(Host), Dial: backend.Listener.Addr().String()},
	}
	handler := Handler{
		logger:    zap.NewNop(),
		Transport: ht,
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	req := httptest.NewRequest("GET", "http://localhost/slow", nil)
	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})
	rec := httptest.NewRecorder()
	err := handler.ServeHTTP(rec, req, nil)
	if err == nil && rec.Code < 400 && rec.Body.String() == "slow response" {
		t.Fatalf("expected standard HTTP request to time out, but succeeded")
	}
}

func TestIntegration_WebSocket_SurvivesReadTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("backend: received request %s %s", r.Method, r.URL.Path)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		t.Logf("backend: writing 101 response")
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()

		t.Logf("backend: sleeping 200ms...")
		time.Sleep(200 * time.Millisecond)
		t.Logf("backend: writing ws-data")
		bufrw.WriteString("ws-data")
		bufrw.Flush()
		t.Logf("backend: done")
	}))
	defer backend.Close()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(80 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	upstreams := UpstreamPool{
		{Host: new(Host), Dial: backend.Listener.Addr().String()},
	}
	handler := Handler{
		logger:        zap.NewNop(),
		Transport:     ht,
		Upstreams:     upstreams,
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer clientLn.Close()

	cConnChan := make(chan net.Conn, 1)
	go func() {
		c, _ := clientLn.Accept()
		cConnChan <- c
	}()

	sConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sConn.Close()

	cConn := <-cConnChan
	defer cConn.Close()

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})

	rec := &hijackableRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		clientConn:       sConn,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		t.Logf("ServeHTTP starting...")
		err := handler.ServeHTTP(rec, req, nil)
		t.Logf("ServeHTTP finished with err: %v", err)
	}()

	reader := bufio.NewReader(cConn)
	t.Logf("reading resLine...")
	resLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed reading upgrade response line: %v", err)
	}
	t.Logf("resLine: %q", resLine)
	if !strings.Contains(resLine, "101") {
		t.Fatalf("expected 101 Switching Protocols response line, got: %q", resLine)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed reading header line: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	t.Logf("headers read successfully")

	buf := make([]byte, 7)
	t.Logf("reading ws-data...")
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		t.Fatalf("failed to read websocket data (idle WebSocket timed out): %v", err)
	}
	t.Logf("read ws-data: %q", string(buf))
	if got := string(buf); got != "ws-data" {
		t.Fatalf("expected 'ws-data', got %q", got)
	}

	cConn.Close()
	t.Logf("waiting for done...")
	<-done
	t.Logf("test complete")
}

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
