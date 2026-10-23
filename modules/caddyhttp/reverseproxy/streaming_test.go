package reverseproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestProtocolCopier_WriteDeadlineTimeout(t *testing.T) {
	clientUser, clientProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer clientUser.Close()
	defer backendServer.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := switchProtocolCopier{
		user:         clientProxy,
		backend:      backendProxy,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	// backendServer sends a payload to backendProxy
	go func() {
		for {
			_, err := backendServer.Write([]byte("hello world payload"))
			if err != nil {
				return
			}
		}
	}()

	// clientUser reads NOTHING (simulating a stalled client connection)

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error on write deadline timeout, got nil")
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// Expected i/o timeout error
		} else if !errors.Is(err, os.ErrDeadlineExceeded) && !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("expected timeout error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("copier blocked indefinitely on stalled socket write")
	}

	// Close connections to unblock the opposing copier
	_ = clientProxy.Close()
	_ = backendProxy.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// wg.Wait() completed successfully without lingering wait state
	case <-time.After(1 * time.Second):
		t.Fatal("wg.Wait() hung on protocol copier teardown")
	}
}

func TestH2ReadWriteCloser_Deadlines(t *testing.T) {
	rec := httptest.NewRecorder()
	rwc := h2ReadWriteCloser{
		ReadCloser:     io.NopCloser(bytes.NewReader(nil)),
		ResponseWriter: rec,
	}

	// Since httptest.ResponseRecorder does not implement SetWriteDeadline,
	// ResponseController returns http.ErrNotSupported.
	err := rwc.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("unexpected error setting write deadline: %v", err)
	}

	err = rwc.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("unexpected error setting read deadline: %v", err)
	}
}

type hijackableRecorder struct {
	http.ResponseWriter
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, nil
}

func TestHandleUpgradeResponse_StalledClientWrite(t *testing.T) {
	clientUser, clientProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer clientUser.Close()
	defer backendServer.Close()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       backendProxy,
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	rw := &hijackableRecorder{
		ResponseWriter: httptest.NewRecorder(),
		conn:           clientProxy,
		rw:             bufio.NewReadWriter(bufio.NewReader(clientProxy), bufio.NewWriter(clientProxy)),
	}

	h := Handler{
		StreamTimeout: caddy.Duration(50 * time.Millisecond),
		connectionsMu: new(sync.Mutex),
		connections:   make(map[io.ReadWriteCloser]openConnection),
	}

	// Backend writes continuous data
	go func() {
		for {
			_, err := backendServer.Write([]byte("backend payload frame"))
			if err != nil {
				return
			}
		}
	}()

	// clientUser reads NOTHING (simulating a stalled client connection)

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// handleUpgradeResponse and wg.Wait() completed cleanly!
	case <-time.After(2 * time.Second):
		t.Fatal("handleUpgradeResponse hung on stalled client write")
	}
}

