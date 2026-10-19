package reverseproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

type mockResponseControllerWriter struct {
	httptest.ResponseRecorder
	mu               sync.Mutex
	writeDeadline    time.Time
	readDeadline     time.Time
	writeUnblockChan chan struct{}
}

func (m *mockResponseControllerWriter) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeDeadline = t
	if !t.IsZero() && t.Before(time.Now()) && m.writeUnblockChan != nil {
		select {
		case <-m.writeUnblockChan:
		default:
			close(m.writeUnblockChan)
		}
	}
	return nil
}

func (m *mockResponseControllerWriter) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readDeadline = t
	return nil
}

func (m *mockResponseControllerWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	dl := m.writeDeadline
	unblockCh := m.writeUnblockChan
	m.mu.Unlock()

	if !dl.IsZero() && dl.Before(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}

	if unblockCh != nil {
		select {
		case <-unblockCh:
			return 0, os.ErrDeadlineExceeded
		default:
		}
	}

	return m.ResponseRecorder.Write(p)
}

func TestH2ReadWriteCloserDeadlinesAndClose(t *testing.T) {
	canceled := false
	cancel := func() { canceled = true }
	rw := &mockResponseControllerWriter{
		writeUnblockChan: make(chan struct{}),
	}
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	rwc := h2ReadWriteCloser{
		ReadCloser:     pr,
		ResponseWriter: rw,
		cancel:         cancel,
	}

	// Test SetWriteDeadline
	now := time.Now()
	if err := rwc.SetWriteDeadline(now.Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline error: %v", err)
	}
	if !rw.writeDeadline.Equal(now.Add(time.Second)) {
		t.Fatalf("writeDeadline not set correctly")
	}

	// Test Close unblocking and context cancellation
	if err := rwc.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if !canceled {
		t.Fatalf("expected cancel func to be called on Close")
	}
	if rw.writeDeadline.IsZero() || !rw.writeDeadline.Before(now) {
		t.Fatalf("expected past write deadline on Close")
	}
}

func TestSwitchProtocolCopierWriteDeadline(t *testing.T) {
	client1, client2 := net.Pipe()
	defer client1.Close()
	defer client2.Close()

	backend1, backend2 := net.Pipe()
	defer backend1.Close()
	defer backend2.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	copier := switchProtocolCopier{
		user:         client1,
		backend:      backend1,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)

	go func() {
		_, _ = backend2.Write([]byte("test data under backpressure"))
	}()

	wg.Wait()
	err := <-errc
	if err == nil {
		t.Fatalf("expected error due to write deadline timeout, got nil")
	}
}

func TestSwitchProtocolCopierDualClose(t *testing.T) {
	client1, client2 := net.Pipe()
	backend1, backend2 := net.Pipe()

	var wg sync.WaitGroup
	var closedCount int32
	closeBoth := func() {
		atomic.AddInt32(&closedCount, 1)
		_ = client1.Close()
		_ = backend1.Close()
	}

	errc := make(chan error, 2)
	copier := switchProtocolCopier{
		user:      client1,
		backend:   backend1,
		wg:        &wg,
		closeBoth: closeBoth,
	}

	wg.Add(2)
	go copier.copyToBackend(errc)
	go copier.copyFromBackend(errc)

	// Close client2 to simulate client disconnect/EOF
	_ = client2.Close()

	wg.Wait()

	if count := atomic.LoadInt32(&closedCount); count == 0 {
		t.Fatalf("expected closeBoth to be called")
	}

	_ = backend2.Close()
}

type mockHijackResponseWriter struct {
	httptest.ResponseRecorder
	conn net.Conn
}

func (m *mockHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn))
	return m.conn, brw, nil
}

func TestHandleUpgradeResponseBackpressureTeardown(t *testing.T) {
	h := &Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
	}

	back1, back2 := net.Pipe()
	defer back1.Close()
	defer back2.Close()

	client1, client2 := net.Pipe()
	defer client1.Close()
	defer client2.Close()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	rw := &mockHijackResponseWriter{
		conn: client1,
	}

	res := &http.Response{
		Header:     http.Header{},
		StatusCode: http.StatusSwitchingProtocols,
		Body:       back1,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		close(done)
	}()

	go func() {
		for {
			_, err := back2.Write([]byte("websocket data frame"))
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
		// Success: handleUpgradeResponse completed when StreamTimeout expired
	case <-time.After(2 * time.Second):
		t.Fatalf("handleUpgradeResponse hung under write backpressure")
	}

	wgWaitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgWaitDone)
	}()

	select {
	case <-wgWaitDone:
		// Success: WaitGroup completed promptly
	case <-time.After(2 * time.Second):
		t.Fatalf("WaitGroup.Wait() hung after handleUpgradeResponse returned")
	}
}
