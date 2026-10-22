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

type mockDeadlinedConn struct {
	io.Reader
	io.Writer
	closed             bool
	deadlineSet        bool
	lastSetDeadline    time.Time
	writeDeadlineErr   error
	setWriteDeadlineErr error
	mu                 sync.Mutex
}

func (m *mockDeadlinedConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deadlineSet = true
	m.lastSetDeadline = t
	return m.setWriteDeadlineErr
}

func (m *mockDeadlinedConn) Write(p []byte) (int, error) {
	m.mu.Lock()
	err := m.writeDeadlineErr
	m.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return m.Writer.Write(p)
}

func (m *mockDeadlinedConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func TestSwitchProtocolCopierWriteDeadlineEnforcement(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	var dst bytes.Buffer
	userConn := &mockDeadlinedConn{
		Reader: strings.NewReader(""),
		Writer: &dst,
	}
	backendConn := &mockDeadlinedConn{
		Reader: strings.NewReader("hello deadlined world"),
		Writer: io.Discard,
	}

	copier := switchProtocolCopier{
		user:         userConn,
		backend:      backendConn,
		wg:           &wg,
		writeTimeout: 100 * time.Millisecond,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("unexpected error from copyFromBackend: %v", err)
	}

	userConn.mu.Lock()
	deadlineSet := userConn.deadlineSet
	userConn.mu.Unlock()

	if !deadlineSet {
		t.Fatalf("expected SetWriteDeadline to be called before write operation")
	}

	if dst.String() != "hello deadlined world" {
		t.Fatalf("got %q, want %q", dst.String(), "hello deadlined world")
	}
}

func TestSwitchProtocolCopierWriteDeadlineTimeoutError(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	userConn := &mockDeadlinedConn{
		Reader:           strings.NewReader(""),
		Writer:           io.Discard,
		writeDeadlineErr: context.DeadlineExceeded,
	}
	backendConn := &mockDeadlinedConn{
		Reader: strings.NewReader("data that triggers write timeout"),
		Writer: io.Discard,
	}

	copier := switchProtocolCopier{
		user:         userConn,
		backend:      backendConn,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)
	wg.Wait()

	err := <-errc
	if err == nil {
		t.Fatalf("expected error from write deadline timeout, got nil")
	}
}

type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

func TestHandleUpgradeResponseTeardownOnBackpressure(t *testing.T) {
	userClient, userServer := net.Pipe()
	defer userClient.Close()

	backClient, backServer := net.Pipe()
	defer backClient.Close()

	handler := Handler{
		WriteTimeout:  caddy.Duration(50 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       backServer,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	rec := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userServer,
		brw:            bufio.NewReadWriter(bufio.NewReader(userServer), bufio.NewWriter(userServer)),
	}

	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		// Simulate backend continuously writing data to backServer
		go func() {
			for i := 0; i < 100; i++ {
				_, werr := backClient.Write([]byte("unconsumed websocket frame payload"))
				if werr != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()

		// Do NOT read from userClient to simulate downstream client backpressure

		handler.handleUpgradeResponse(caddy.Log(), &wg, rec, req, res)
		close(done)
	}()

	select {
	case <-done:
		// Success - handleUpgradeResponse exited when write deadline hit
	case <-time.After(3 * time.Second):
		t.Fatalf("handleUpgradeResponse blocked indefinitely under backpressure")
	}

	// Verify wg.Wait() unblocks immediately because both connections were closed
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatalf("wg.Wait() failed to unblock after handleUpgradeResponse connection teardown")
	}
}

func TestHandleUpgradeResponseContextCancellation(t *testing.T) {
	userClient, userServer := net.Pipe()
	defer userClient.Close()

	backClient, backServer := net.Pipe()
	defer backClient.Close()

	handler := Handler{
		WriteTimeout:  caddy.Duration(5 * time.Second),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	ctx, cancel := context.WithCancel(context.Background())

	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       backServer,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	rec := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           userServer,
		brw:            bufio.NewReadWriter(bufio.NewReader(userServer), bufio.NewWriter(userServer)),
	}

	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		handler.handleUpgradeResponse(caddy.Log(), &wg, rec, req, res)
		close(done)
	}()

	// Cancel context after 50ms
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success - handleUpgradeResponse exited promptly upon context cancellation
	case <-time.After(3 * time.Second):
		t.Fatalf("handleUpgradeResponse failed to exit upon context cancellation")
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatalf("wg.Wait() failed to unblock after context cancellation teardown")
	}
}

