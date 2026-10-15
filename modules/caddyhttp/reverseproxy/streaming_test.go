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

	"go.uber.org/zap"

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

type hijackableResponseWriter struct {
	header http.Header
	conn   net.Conn
	rw     *bufio.ReadWriter
}

func (h *hijackableResponseWriter) Header() http.Header {
	if h.header == nil {
		h.header = make(http.Header)
	}
	return h.header
}

func (h *hijackableResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (h *hijackableResponseWriter) WriteHeader(statusCode int) {}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, nil
}

func TestStreamTimeoutActivityReset(t *testing.T) {
	// Scenario 1: Idle connection times out after StreamTimeout.
	t.Run("idle_connection_times_out", func(t *testing.T) {
		clientConn, clientSide := net.Pipe()
		serverConn, backendSide := net.Pipe()
		defer clientSide.Close()
		defer backendSide.Close()

		h := &Handler{
			StreamTimeout: caddy.Duration(100 * time.Millisecond),
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
			Body:       serverConn,
		}
		res.Header.Set("Connection", "Upgrade")
		res.Header.Set("Upgrade", "websocket")

		rw := &hijackableResponseWriter{
			conn: clientConn,
			rw:   bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		}

		var wg sync.WaitGroup
		doneCh := make(chan struct{})

		start := time.Now()
		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
			wg.Wait()
			close(doneCh)
		}()

		select {
		case <-doneCh:
			elapsed := time.Since(start)
			if elapsed < 80*time.Millisecond {
				t.Fatalf("timed out too early: %v", elapsed)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("stream did not time out as expected")
		}
	})

	// Scenario 2: Active connection resetting timer prevents timeout trigger.
	t.Run("active_connection_resets_timeout", func(t *testing.T) {
		clientConn, clientSide := net.Pipe()
		serverConn, backendSide := net.Pipe()
		defer clientSide.Close()
		defer backendSide.Close()

		h := &Handler{
			StreamTimeout: caddy.Duration(120 * time.Millisecond),
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
			Body:       serverConn,
		}
		res.Header.Set("Connection", "Upgrade")
		res.Header.Set("Upgrade", "websocket")

		rw := &hijackableResponseWriter{
			conn: clientConn,
			rw:   bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		}

		var wg sync.WaitGroup
		doneCh := make(chan struct{})

		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
			wg.Wait()
			close(doneCh)
		}()

		// Continuously drain readers in background so pipe writes don't block
		go func() {
			buf := make([]byte, 100)
			for {
				_, err := clientSide.Read(buf)
				if err != nil {
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 100)
			for {
				_, err := backendSide.Read(buf)
				if err != nil {
					return
				}
			}
		}()

		// Send frames every 40ms for 240ms total (longer than 120ms StreamTimeout)
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()

		stopFrames := time.After(240 * time.Millisecond)
	activeLoop:
		for {
			select {
			case <-ticker.C:
				_, err := clientSide.Write([]byte("ping"))
				if err != nil {
					t.Fatalf("failed writing ping: %v", err)
				}
			case <-stopFrames:
				break activeLoop
			case <-doneCh:
				t.Fatal("stream timed out prematurely during active data transfers")
			}
		}

		// Ensure stream is still open after 240ms of active traffic
		select {
		case <-doneCh:
			t.Fatal("stream closed prematurely immediately after active traffic stopped")
		default:
			// Stream is still open as expected!
		}

		// Now allow stream to be idle and verify it times out
		select {
		case <-doneCh:
			// Timed out cleanly after inactivity
		case <-time.After(1 * time.Second):
			t.Fatal("stream failed to time out after activity stopped")
		}
	})

	// Scenario 3: Active connection with backend-initiated transfers resets timeout trigger.
	t.Run("active_connection_backend_resets_timeout", func(t *testing.T) {
		clientConn, clientSide := net.Pipe()
		serverConn, backendSide := net.Pipe()
		defer clientSide.Close()
		defer backendSide.Close()

		h := &Handler{
			StreamTimeout: caddy.Duration(120 * time.Millisecond),
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
			Body:       serverConn,
		}
		res.Header.Set("Connection", "Upgrade")
		res.Header.Set("Upgrade", "websocket")

		rw := &hijackableResponseWriter{
			conn: clientConn,
			rw:   bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		}

		var wg sync.WaitGroup
		doneCh := make(chan struct{})

		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
			wg.Wait()
			close(doneCh)
		}()

		// Continuously drain readers in background
		go func() {
			buf := make([]byte, 100)
			for {
				_, err := clientSide.Read(buf)
				if err != nil {
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 100)
			for {
				_, err := backendSide.Read(buf)
				if err != nil {
					return
				}
			}
		}()

		// Backend sends frames every 40ms for 240ms total (longer than 120ms StreamTimeout)
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()

		stopFrames := time.After(240 * time.Millisecond)
	activeLoop:
		for {
			select {
			case <-ticker.C:
				_, err := backendSide.Write([]byte("pong"))
				if err != nil {
					t.Fatalf("failed writing pong from backend: %v", err)
				}
			case <-stopFrames:
				break activeLoop
			case <-doneCh:
				t.Fatal("stream timed out prematurely during active backend data transfers")
			}
		}

		// Ensure stream is still open after 240ms of active backend traffic
		select {
		case <-doneCh:
			t.Fatal("stream closed prematurely immediately after active backend traffic stopped")
		default:
			// Stream is still open as expected!
		}

		// Now allow stream to be idle and verify it times out
		select {
		case <-doneCh:
			// Timed out cleanly after inactivity
		case <-time.After(1 * time.Second):
			t.Fatal("stream failed to time out after backend activity stopped")
		}
	})
}
