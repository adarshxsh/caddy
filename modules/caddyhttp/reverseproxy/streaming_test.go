package reverseproxy

import (
	"bufio"
	"bytes"
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

func TestActivityReadWriteCloser(t *testing.T) {
	var activityCount int
	onActivity := func() {
		activityCount++
	}

	raw := &rwMock{
		readData:  []byte("hello"),
		writeData: make([]byte, 10),
	}

	arwc := &activityReadWriteCloser{
		ReadWriteCloser: raw,
		onActivity:      onActivity,
	}

	buf := make([]byte, 10)
	n, err := arwc.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("Read failed: n=%d, err=%v", n, err)
	}
	if activityCount != 1 {
		t.Errorf("expected activityCount=1 after non-zero read, got %d", activityCount)
	}

	// zero byte read
	n, err = arwc.Read(buf[:0])
	if n != 0 {
		t.Fatalf("expected 0 read, got %d", n)
	}
	if activityCount != 1 {
		t.Errorf("expected activityCount=1 after zero-byte read, got %d", activityCount)
	}

	// non-zero write
	n, err = arwc.Write([]byte("test"))
	if err != nil || n != 4 {
		t.Fatalf("Write failed: n=%d, err=%v", n, err)
	}
	if activityCount != 2 {
		t.Errorf("expected activityCount=2 after non-zero write, got %d", activityCount)
	}

	// zero byte write
	n, err = arwc.Write(nil)
	if n != 0 {
		t.Fatalf("expected 0 write, got %d", n)
	}
	if activityCount != 2 {
		t.Errorf("expected activityCount=2 after zero-byte write, got %d", activityCount)
	}
}

type rwMock struct {
	readData  []byte
	writeData []byte
}

func (m *rwMock) Read(p []byte) (int, error) {
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(p, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *rwMock) Write(p []byte) (int, error) {
	_ = copy(m.writeData, p)
	return len(p), nil
}

func (m *rwMock) Close() error { return nil }

type mockHijackerConn struct {
	http.ResponseWriter
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (m *mockHijackerConn) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

func TestStreamIdleTimeout(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        caddy.Log(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	rw := &mockHijackerConn{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyClientConn,
		brw:            bufio.NewReadWriter(bufio.NewReader(proxyClientConn), bufio.NewWriter(proxyClientConn)),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	start := time.Now()
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < 100*time.Millisecond || elapsed > 500*time.Millisecond {
			t.Errorf("expected timeout around 150ms, took %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("stream did not time out when idle")
	}
}

func TestActiveStreamDoesNotTimeout(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        caddy.Log(),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	rw := &mockHijackerConn{
		ResponseWriter: httptest.NewRecorder(),
		conn:           proxyClientConn,
		brw:            bufio.NewReadWriter(bufio.NewReader(proxyClientConn), bufio.NewWriter(proxyClientConn)),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	// Send periodic traffic for 400ms (exceeding 150ms timeout)
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		buf := make([]byte, 1)
		for {
			select {
			case <-stopPing:
				return
			case <-ticker.C:
				_, _ = clientConn.Write([]byte("a"))
				_, _ = serverConn.Read(buf)
			}
		}
	}()

	// Sleep 350ms to verify connection stays alive
	time.Sleep(350 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("active stream timed out unexpectedly during traffic")
	default:
		// Active stream is still open, as expected
	}

	// Stop sending traffic and verify it times out afterwards
	close(stopPing)
	start := time.Now()
	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 500*time.Millisecond {
			t.Errorf("stream took too long to time out after traffic stopped: %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("stream did not time out after traffic stopped")
	}
}

func TestHTTP2ExtendedConnectStreamTimeout(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyBackConn, serverConn := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
		logger:        caddy.Log(),
	}

	req := httptest.NewRequest("CONNECT", "/", nil)
	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})
	caddyhttp.SetVar(req.Context(), "extended_connect_websocket_body", proxyClientConn)
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       proxyBackConn,
	}
	res.Header.Set("Upgrade", "websocket")

	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	done := make(chan struct{})

	start := time.Now()
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rec, req, res)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < 100*time.Millisecond || elapsed > 500*time.Millisecond {
			t.Errorf("expected timeout around 150ms, took %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("h2 stream did not time out when idle")
	}
}


