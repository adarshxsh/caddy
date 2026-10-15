package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

func TestTcpRWTimeoutConnDisableTimeouts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(150 * time.Millisecond)
		_, _ = conn.Write([]byte("hello"))
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", clientConn)
	}

	rwConn := &tcpRWTimeoutConn{
		TCPConn:     tcpConn,
		readTimeout: 50 * time.Millisecond,
	}

	rwConn.DisableTimeouts()

	if rwConn.readTimeout != 0 || rwConn.writeTimeout != 0 {
		t.Fatalf("expected timeouts to be 0, got readTimeout=%v writeTimeout=%v", rwConn.readTimeout, rwConn.writeTimeout)
	}

	buf := make([]byte, 10)
	n, err := rwConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed unexpectedly: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hello")
	}

	<-serverDone
}

type testWrappedConn struct {
	net.Conn
}

func (w testWrappedConn) Unwrap() net.Conn {
	return w.Conn
}

func TestDisableConnectionTimeouts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	tcpConn := clientConn.(*net.TCPConn)

	t.Run("plain tcpRWTimeoutConn", func(t *testing.T) {
		rwConn := &tcpRWTimeoutConn{
			TCPConn:     tcpConn,
			readTimeout: 100 * time.Millisecond,
		}
		disableConnectionTimeouts(rwConn)
		if rwConn.readTimeout != 0 {
			t.Errorf("expected readTimeout to be 0, got %v", rwConn.readTimeout)
		}
	})

	t.Run("tls wrapped tcpRWTimeoutConn", func(t *testing.T) {
		rwConn := &tcpRWTimeoutConn{
			TCPConn:     tcpConn,
			readTimeout: 100 * time.Millisecond,
		}
		tlsConn := tls.Client(rwConn, &tls.Config{InsecureSkipVerify: true})
		disableConnectionTimeouts(tlsConn)
		if rwConn.readTimeout != 0 {
			t.Errorf("expected readTimeout to be 0, got %v", rwConn.readTimeout)
		}
	})

	t.Run("custom unwrappable connection", func(t *testing.T) {
		rwConn := &tcpRWTimeoutConn{
			TCPConn:     tcpConn,
			readTimeout: 100 * time.Millisecond,
		}
		tlsConn := tls.Client(rwConn, &tls.Config{InsecureSkipVerify: true})
		wrapped := testWrappedConn{Conn: tlsConn}
		disableConnectionTimeouts(wrapped)
		if rwConn.readTimeout != 0 {
			t.Errorf("expected readTimeout to be 0, got %v", rwConn.readTimeout)
		}
	})

	t.Run("nil connection", func(t *testing.T) {
		disableConnectionTimeouts(nil)
	})
}

func TestHandleUpgradeResponseDisableTimeouts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "not websocket", 400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer conn.Close()

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()

		time.Sleep(150 * time.Millisecond)

		buf := make([]byte, 1024)
		n, err := bufrw.Read(buf)
		if err == nil && n > 0 {
			_, _ = bufrw.Write(buf[:n])
			_ = bufrw.Flush()
		}
	}))
	defer backend.Close()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ht := &HTTPTransport{
		ReadTimeout:  caddy.Duration(50 * time.Millisecond),
		WriteTimeout: caddy.Duration(50 * time.Millisecond),
	}
	_ = ht.Provision(ctx)

	handler := &Handler{
		Upstreams: UpstreamPool{&Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()}},
		Transport: ht,
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        zap.NewNop(),
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), nil, &caddyhttp.Server{})
		err := handler.ServeHTTP(w, r, nil)
		if err != nil {
			t.Logf("ServeHTTP error: %v", err)
		}
	}))
	defer proxyServer.Close()

	req, err := http.NewRequest("GET", proxyServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	clientConn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer clientConn.Close()

	err = req.Write(clientConn)
	if err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	bufrw := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
	res, err := http.ReadResponse(bufrw.Reader, req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("expected status 101, got %d", res.StatusCode)
	}

	time.Sleep(150 * time.Millisecond)

	testMsg := "ping"
	_, err = bufrw.Writer.WriteString(testMsg)
	if err != nil {
		t.Fatalf("failed to write to upgraded connection: %v", err)
	}
	_ = bufrw.Writer.Flush()

	reply := make([]byte, 10)
	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := bufrw.Reader.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}
	if string(reply[:n]) != testMsg {
		t.Fatalf("got reply %q, want %q", string(reply[:n]), testMsg)
	}
}
