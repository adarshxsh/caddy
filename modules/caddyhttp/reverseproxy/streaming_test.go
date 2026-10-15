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

type mockUnwrapNetConn struct {
	conn net.Conn
}

func (m mockUnwrapNetConn) Unwrap() net.Conn {
	return m.conn
}

type mockUnwrapRWC struct {
	rwc io.ReadWriteCloser
}

func (m mockUnwrapRWC) Unwrap() io.ReadWriteCloser {
	return m.rwc
}

type mockUnwrapAny struct {
	item any
}

func (m mockUnwrapAny) Unwrap() any {
	return m.item
}

type mockDisableTimeoutsConn struct {
	disabled bool
}

func (m *mockDisableTimeoutsConn) DisableTimeouts() error {
	m.disabled = true
	return nil
}

func TestDeactivateConnectionTimeouts(t *testing.T) {
	t.Run("Mock connection unwrapping", func(t *testing.T) {
		m := &mockDisableTimeoutsConn{}
		wrapper1 := mockUnwrapNetConn{conn: nil}
		wrapper2 := mockUnwrapRWC{rwc: nopReadWriteCloser{}}
		wrapper3 := mockUnwrapAny{item: m}

		deactivateConnectionTimeouts(wrapper3)
		if !m.disabled {
			t.Errorf("expected mockDisableTimeoutsConn to be disabled through Unwrap")
		}

		// Graceful non-panic on normal connection wrappers
		deactivateConnectionTimeouts(wrapper1)
		deactivateConnectionTimeouts(wrapper2)
	})

	t.Run("Real tcpRWTimeoutConn and Unwrap wrappers", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer ln.Close()

		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer client.Close()

		tc := &tcpRWTimeoutConn{
			TCPConn: client.(*net.TCPConn),
			logger:  zap.NewNop(),
		}
		tc.readTimeout.Store(int64(100 * time.Millisecond))
		tc.writeTimeout.Store(int64(100 * time.Millisecond))

		wrapped := mockUnwrapAny{item: mockUnwrapNetConn{conn: tc}}
		deactivateConnectionTimeouts(wrapped)

		if tc.readTimeout.Load() != 0 || tc.writeTimeout.Load() != 0 {
			t.Errorf("expected timeouts to be disabled, got read=%d write=%d", tc.readTimeout.Load(), tc.writeTimeout.Load())
		}
	})
}

func TestHandleUpgradeResponse_DisableTimeouts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	// Backend server logic
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}

		if req.Header.Get("Upgrade") != "websocket" {
			return
		}

		// Write 101 Switching Protocols
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZIZzA5M0=\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Wait 150ms (idle period longer than the 50ms transport ReadTimeout)
		time.Sleep(150 * time.Millisecond)

		// Read frame from client
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		// Echo back to client
		_, _ = conn.Write(buf[:n])
	}()

	// Simulate dial with tcpRWTimeoutConn having 50ms read/write timeouts
	dialConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer dialConn.Close()

	tcpConn := dialConn.(*net.TCPConn)
	timeoutConn := &tcpRWTimeoutConn{
		TCPConn: tcpConn,
		logger:  zap.NewNop(),
	}
	timeoutConn.readTimeout.Store(int64(50 * time.Millisecond))
	timeoutConn.writeTimeout.Store(int64(50 * time.Millisecond))

	// Send Upgrade HTTP request on backend conn
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String(), nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	err = req.Write(timeoutConn)
	if err != nil {
		t.Fatalf("Request write failed: %v", err)
	}

	br := bufio.NewReader(timeoutConn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}
	res.Body = timeoutConn // HTTP transport attaches raw socket to res.Body on 101

	// Setup Handler and ResponseWriter with Hijacker using net.Pipe
	h := &Handler{
		logger:        zap.NewNop(),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	clientConn, hijackConn := net.Pipe()

	rw := &netPipeResponseWriter{
		conn: hijackConn,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.handleUpgradeResponse(zap.NewNop(), &sync.WaitGroup{}, rw, req, res)
	}()

	// Wait 150ms (longer than 50ms ReadTimeout) to verify WebSocket didn't time out
	time.Sleep(150 * time.Millisecond)

	// Write payload from client side
	testPayload := []byte("ping-websocket-idle")
	go func() {
		_, _ = clientConn.Write(testPayload)
	}()

	buf := make([]byte, 100)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read echo failed: %v", err)
	}

	if string(buf[:n]) != string(testPayload) {
		t.Fatalf("got echo %q, want %q", string(buf[:n]), string(testPayload))
	}

	clientConn.Close()
	hijackConn.Close()
	wg.Wait()
}

func TestHTTPTransport_StandardRequestTimeoutEnforcement(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	// Slow backend server that accepts conn and receives request but does NOT respond
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		time.Sleep(200 * time.Millisecond)
	}()

	caddyCtx, cancelCtx := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancelCtx()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(50 * time.Millisecond),
	}
	if err := ht.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	reqCtx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
		caddyhttp.TrustedProxyVarKey: false,
	})
	req = req.WithContext(reqCtx)

	resp, err := ht.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected RoundTrip to fail due to ReadTimeout, but it succeeded")
	}
}

type netPipeResponseWriter struct {
	httptest.ResponseRecorder
	conn net.Conn
}

func (n *netPipeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(n.conn), bufio.NewWriter(n.conn))
	return n.conn, brw, nil
}
