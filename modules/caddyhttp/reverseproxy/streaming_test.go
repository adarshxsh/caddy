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
	"net/url"
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

type nestedConnWrapper struct {
	net.Conn
}

func (w nestedConnWrapper) Unwrap() net.Conn {
	return w.Conn
}

func TestClearDeadline_NestedUnwrap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}

	timeoutConn := &tcpRWTimeoutConn{
		TCPConn: tcpConn,
		logger:  zap.NewNop(),
	}
	timeoutConn.readTimeout.Store(int64(500 * time.Millisecond))
	timeoutConn.writeTimeout.Store(int64(500 * time.Millisecond))

	nested := nestedConnWrapper{Conn: timeoutConn}

	clearDeadline(nested)

	if got := timeoutConn.readTimeout.Load(); got != 0 {
		t.Errorf("readTimeout after clearDeadline(nested) = %d, want 0", got)
	}
	if got := timeoutConn.writeTimeout.Load(); got != 0 {
		t.Errorf("writeTimeout after clearDeadline(nested) = %d, want 0", got)
	}
}

func TestProtocolUpgrade_IdlePersistence(t *testing.T) {
	// Backend server supporting 101 Switching Protocols
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.SetDeadline(time.Time{})

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()

		// Echo back data received from client
		buf := make([]byte, 1024)
		n, err := bufrw.Read(buf)
		if err != nil {
			t.Logf("backend bufrw.Read error: %v", err)
		} else {
			bufrw.Write(buf[:n])
			bufrw.Flush()
		}
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	// Reverse proxy handler with short transport ReadTimeout (100ms)
	transport := &HTTPTransport{
		ReadTimeout: caddy.Duration(100 * time.Millisecond),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := transport.Provision(ctx); err != nil {
		t.Fatalf("failed to provision transport: %v", err)
	}

	upstream := &Upstream{
		Dial: backendURL.Host,
		Host: new(Host),
	}

	handler := &Handler{
		logger:        zap.NewNop(),
		Transport:     transport,
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		Upstreams:     UpstreamPool{upstream},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCtx := r.Context()
		reqCtx = context.WithValue(reqCtx, caddy.ReplacerCtxKey, caddy.NewReplacer())
		reqCtx = context.WithValue(reqCtx, caddyhttp.VarsCtxKey, make(map[string]any))
		reqCtx = context.WithValue(reqCtx, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
		caddyhttp.SetVar(reqCtx, caddyhttp.ClientIPVarKey, "127.0.0.1")
		caddyhttp.SetVar(reqCtx, caddyhttp.TrustedProxyVarKey, false)
		_ = handler.ServeHTTP(w, r.WithContext(reqCtx), nil)
	})
	proxyServer := httptest.NewServer(serverHandler)
	defer proxyServer.Close()

	// Dial proxy server directly
	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer conn.Close()

	// Send HTTP upgrade request
	reqStr := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", proxyURL.Host)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("failed to write upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	// Read 101 Switching Protocols status line
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line: %v", err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("expected 101 status line, got: %q", line)
	}

	// Consume remaining response headers
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil || headerLine == "\r\n" {
			break
		}
	}

	// Connection is now upgraded.
	// Sleep for 300ms (greater than transport ReadTimeout of 100ms) while connection is idle.
	time.Sleep(300 * time.Millisecond)

	// Now send data over the upgraded connection
	testPayload := "ping-after-idle"
	if _, err := conn.Write([]byte(testPayload)); err != nil {
		t.Fatalf("failed to write data after idle period: %v", err)
	}

	buf := make([]byte, len(testPayload))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("failed to read response after idle period: %v (connection dropped prematurely)", err)
	}

	if string(buf) != testPayload {
		t.Errorf("got payload %q, want %q", string(buf), testPayload)
	}
}
