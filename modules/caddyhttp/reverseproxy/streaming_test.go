package reverseproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestExtractTCPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	var serverConn net.Conn
	go func() {
		defer close(done)
		var acceptErr error
		serverConn, acceptErr = ln.Accept()
		if acceptErr != nil {
			return
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()
	<-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	tcpClient, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("clientConn is not *net.TCPConn")
	}

	// 1. Direct *net.TCPConn
	if extracted := extractTCPConn(clientConn); extracted != tcpClient {
		t.Errorf("extractTCPConn(clientConn) = %v, want %v", extracted, tcpClient)
	}

	// 2. Struct embedding *net.TCPConn
	type customTCPWrapper struct {
		*net.TCPConn
	}
	wrapper := customTCPWrapper{TCPConn: tcpClient}
	if extracted := extractTCPConn(wrapper); extracted != tcpClient {
		t.Errorf("extractTCPConn(customTCPWrapper) = %v, want %v", extracted, tcpClient)
	}

	// 3. struct with Conn field (like hijackedConn)
	type mockHijackedConn struct {
		net.Conn
	}
	hc := &mockHijackedConn{Conn: clientConn}
	if extracted := extractTCPConn(hc); extracted != tcpClient {
		t.Errorf("extractTCPConn(mockHijackedConn) = %v, want %v", extracted, tcpClient)
	}

	// 4. tcpRWTimeoutConn struct
	trwc := &tcpRWTimeoutConn{TCPConn: tcpClient}
	if extracted := extractTCPConn(trwc); extracted != tcpClient {
		t.Errorf("extractTCPConn(tcpRWTimeoutConn) = %v, want %v", extracted, tcpClient)
	}

	// 5. struct with NetConn method or tlsNetConn
	type mockTLSStateConn struct {
		conn net.Conn
	}
	tsc := mockTLSStateConn{conn: clientConn}
	if extracted := extractTCPConn(tsc.conn); extracted != tcpClient {
		t.Errorf("extractTCPConn(mockTLSStateConn) = %v, want %v", extracted, tcpClient)
	}

	// 6. Non-TCP connection (net.Pipe)
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if extracted := extractTCPConn(p1); extracted != nil {
		t.Errorf("extractTCPConn(net.Pipe) = %v, want nil", extracted)
	}
}

func TestSetTCPKeepAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
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
	<-done

	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn")
	}

	err = setTCPKeepAlive(tcpConn, 10*time.Second)
	if err != nil {
		t.Fatalf("setTCPKeepAlive error: %v", err)
	}
}

func TestCaddyfileStreamKeepAlive(t *testing.T) {
	tests := []struct {
		input    string
		expected caddy.Duration
		hasErr   bool
	}{
		{
			input:    `reverse_proxy 127.0.0.1:8080 { stream_keepalive 10s }`,
			expected: caddy.Duration(10 * time.Second),
		},
		{
			input:    `reverse_proxy 127.0.0.1:8080 { stream_keepalive off }`,
			expected: caddy.Duration(-1),
		},
		{
			input:    `reverse_proxy 127.0.0.1:8080 { stream_keepalive disabled }`,
			expected: caddy.Duration(-1),
		},
		{
			input:    `reverse_proxy 127.0.0.1:8080 { stream_keepalive 500ms }`,
			expected: caddy.Duration(500 * time.Millisecond),
		},
	}

	for _, tt := range tests {
		d := caddyfile.NewTestDispenser(tt.input)
		h := new(Handler)
		err := h.UnmarshalCaddyfile(d)
		if (err != nil) != tt.hasErr {
			t.Errorf("input %q: unexpected error status %v (err: %v)", tt.input, tt.hasErr, err)
			continue
		}
		if !tt.hasErr && h.StreamKeepAlive != tt.expected {
			t.Errorf("input %q: got StreamKeepAlive %v, want %v", tt.input, h.StreamKeepAlive, tt.expected)
		}
	}
}

func TestUpgradeStreamingKeepAlive(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("backend server ResponseWriter not Hijacker")
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Errorf("backend Hijack failed: %v", err)
			return
		}
		defer conn.Close()

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()

		buf := make([]byte, 1024)
		n, err := bufrw.Read(buf)
		if err == nil {
			bufrw.Write(buf[:n])
			bufrw.Flush()
		}
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	u := &Upstream{Dial: backendURL.Host}
	tTransport := &HTTPTransport{}
	_ = tTransport.Provision(caddy.Context{})

	h := &Handler{
		Upstreams:       UpstreamPool{u},
		StreamKeepAlive: caddy.Duration(1 * time.Second),
		Transport:       tTransport,
		LoadBalancing:   &LoadBalancing{SelectionPolicy: RandomSelection{}},
		logger:          caddy.Log(),
		connections:     make(map[io.ReadWriteCloser]openConnection),
		connectionsMu:   new(sync.Mutex),
	}
	h.provisionUpstream(u, false)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
		_ = h.ServeHTTP(w, req, nil)
	}))
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	clientConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}
	defer clientConn.Close()

	reqStr := "GET /ws HTTP/1.1\r\nHost: " + proxyURL.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	_, err = clientConn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	bufrw := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
	res, err := http.ReadResponse(bufrw.Reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status 101, got %d", res.StatusCode)
	}

	clientConn.Write([]byte("ping"))
	buf := make([]byte, 10)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read back echo: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "ping")
	}
}
