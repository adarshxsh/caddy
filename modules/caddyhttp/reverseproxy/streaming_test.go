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

type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (m mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, nil
}

func TestStreamTimeoutIdleClose(t *testing.T) {
	clientConnServer, clientConnClient := net.Pipe()
	backendConnServer, backendConnClient := net.Pipe()
	defer clientConnClient.Close()
	defer backendConnClient.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(100 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: backendConnServer,
	}

	rw := mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           clientConnServer,
		rw:             bufio.NewReadWriter(bufio.NewReader(clientConnServer), bufio.NewWriter(clientConnServer)),
	}

	start := time.Now()
	var wg sync.WaitGroup
	h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
	wg.Wait()
	elapsed := time.Since(start)

	if elapsed < 90*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("expected stream to close around 100ms, but took %v", elapsed)
	}
}

func TestStreamTimeoutActivityReset(t *testing.T) {
	clientConnServer, clientConnClient := net.Pipe()
	backendConnServer, backendConnClient := net.Pipe()
	defer clientConnClient.Close()
	defer backendConnClient.Close()

	h := Handler{
		StreamTimeout: caddy.Duration(150 * time.Millisecond),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
		Body: backendConnServer,
	}

	rw := mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           clientConnServer,
		rw:             bufio.NewReadWriter(bufio.NewReader(clientConnServer), bufio.NewWriter(clientConnServer)),
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		h.handleUpgradeResponse(caddy.Log(), &wg, rw, req, res)
		wg.Wait()
		close(done)
	}()

	start := time.Now()

	// Drain backend in background
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := backendConnClient.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Keep connection active by sending data every 50ms for 350ms (total time > 2x timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	stopPings := time.After(350 * time.Millisecond)
activeLoop:
	for {
		select {
		case <-ticker.C:
			_, err := clientConnClient.Write([]byte("ping"))
			if err != nil {
				t.Fatalf("write failed: %v", err)
			}
		case <-stopPings:
			break activeLoop
		case <-done:
			t.Fatalf("connection closed prematurely while active after %v", time.Since(start))
		}
	}

	activeDuration := time.Since(start)
	if activeDuration < 300*time.Millisecond {
		t.Fatalf("active phase ended too early: %v", activeDuration)
	}

	// Now stop sending data and wait for idle timeout (150ms)
	select {
	case <-done:
		totalElapsed := time.Since(start)
		// Should take around 350ms + 150ms = 500ms
		if totalElapsed < 450*time.Millisecond {
			t.Fatalf("stream closed too quickly after activity stopped: total elapsed %v", totalElapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("stream failed to close after activity stopped")
	}
}
