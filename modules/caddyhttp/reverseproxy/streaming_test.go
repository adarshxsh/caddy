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

func TestHandleUpgradeResponse_UnwrapsAndClearsDeadlines(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 100)
			_, _ = c.Read(buf)
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer clientConn.Close()

	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", clientConn)
	}

	timeoutConn := &tcpRWTimeoutConn{
		TCPConn: tcpConn,
		logger:  zap.NewNop(),
	}
	timeoutConn.readTimeout.Store(int64(50 * time.Millisecond))
	timeoutConn.writeTimeout.Store(int64(50 * time.Millisecond))

	h := &Handler{
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       timeoutConn,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	// Run handleUpgradeResponse in goroutine
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(zap.NewNop(), &wg, rec, req, res)
		close(done)
	}()

	// Give handleUpgradeResponse time to set up
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}

	// Verify timeouts on timeoutConn were cleared to 0
	if got := time.Duration(timeoutConn.readTimeout.Load()); got != 0 {
		t.Fatalf("readTimeout = %v, want 0", got)
	}
	if got := time.Duration(timeoutConn.writeTimeout.Load()); got != 0 {
		t.Fatalf("writeTimeout = %v, want 0", got)
	}
}

func TestWebSocket_TransportTimeout_RemainsOpen(t *testing.T) {
	// 1. Create a backend server that performs 101 Switching Protocols upgrade
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Wait 150ms idle (longer than the 50ms transport timeout)
		time.Sleep(150 * time.Millisecond)

		// Send a message to client
		_, _ = conn.Write([]byte("ping_from_backend"))

		// Read response from client
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err == nil && string(buf[:n]) == "pong_from_client" {
			_, _ = conn.Write([]byte("ok_end"))
		}
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ht := &HTTPTransport{
		ReadTimeout:  caddy.Duration(50 * time.Millisecond),
		WriteTimeout: caddy.Duration(50 * time.Millisecond),
	}
	if err := ht.Provision(ctx); err != nil {
		t.Fatalf("HTTPTransport.Provision failed: %v", err)
	}

	reverseProxyHandler := &Handler{
		Transport: ht,
		Upstreams: UpstreamPool{&Upstream{
			Dial: backendLn.Addr().String(),
			Host: &Host{},
		}},
		LoadBalancing: &LoadBalancing{SelectionPolicy: &RandomSelection{}},
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCtx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
			caddyhttp.ClientIPVarKey:     "127.0.0.1",
			caddyhttp.TrustedProxyVarKey: false,
		})
		reqCtx = context.WithValue(reqCtx, caddy.ReplacerCtxKey, caddy.NewReplacer())
		reqCtx = context.WithValue(reqCtx, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
		r = r.WithContext(reqCtx)

		_ = reverseProxyHandler.ServeHTTP(w, r, nil)
	}))
	defer proxyServer.Close()

	// Client dials proxy
	clientConn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientConn.Close()

	reqStr := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", proxyServer.Listener.Addr().String())
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request failed: %v", err)
	}

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("client read response failed: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Read message sent by backend after idle period
	msgBuf := make([]byte, 100)
	n, err := br.Read(msgBuf)
	if err != nil {
		t.Fatalf("client failed to read after idle period: %v", err)
	}
	if string(msgBuf[:n]) != "ping_from_backend" {
		t.Fatalf("got %q, want ping_from_backend", string(msgBuf[:n]))
	}

	// Send pong to backend
	if _, err := clientConn.Write([]byte("pong_from_client")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	n, err = br.Read(msgBuf)
	if err != nil {
		t.Fatalf("client failed final read: %v", err)
	}
	if string(msgBuf[:n]) != "ok_end" {
		t.Fatalf("got %q, want ok_end", string(msgBuf[:n]))
	}
}
