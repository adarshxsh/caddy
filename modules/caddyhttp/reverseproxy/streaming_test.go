package reverseproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestSwitchProtocolCopierOnActivity(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	b1, b2 := net.Pipe()
	defer b1.Close()
	defer b2.Close()

	var activityCount int32
	var wg sync.WaitGroup
	errc := make(chan error, 2)

	copier := switchProtocolCopier{
		user:    c1,
		backend: b1,
		wg:      &wg,
		onActivity: func() {
			atomic.AddInt32(&activityCount, 1)
		},
	}

	wg.Add(2)
	go copier.copyToBackend(errc)
	go copier.copyFromBackend(errc)

	// Send data from c2 -> c1 (user) -> b1 (backend) -> b2
	go func() {
		c2.Write([]byte("ping"))
	}()

	buf := make([]byte, 10)
	n, err := b2.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("unexpected read from backend: %v, %s", err, string(buf[:n]))
	}

	if atomic.LoadInt32(&activityCount) == 0 {
		t.Fatal("expected activityCount > 0 after transferring data")
	}

	c1.Close()
	b1.Close()
	c2.Close()
	b2.Close()
	wg.Wait()
}

func TestHandleUpgradeResponse_ActivityBasedTimeout(t *testing.T) {
	streamTimeout := 200 * time.Millisecond

	// Create backend server that responds with 101 Switching Protocols
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()

		// Echo messages back to client
		buf := make([]byte, 1024)
		for {
			n, err := bufrw.Read(buf)
			if err != nil {
				return
			}
			bufrw.Write(buf[:n])
			bufrw.Flush()
		}
	}))
	defer backend.Close()

	// Handler with StreamTimeout set
	h := &Handler{
		StreamTimeout: caddy.Duration(streamTimeout),
		connections:   make(map[io.ReadWriteCloser]openConnection),
		connectionsMu: new(sync.Mutex),
	}

	// Create proxy server using handleUpgradeResponse
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward request to backend
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, backend.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		outReq.Header = r.Header.Clone()

		res, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer res.Body.Close()

		var wg sync.WaitGroup
		h.handleUpgradeResponse(caddy.Log(), &wg, w, r, res)
		wg.Wait()
	}))
	defer proxy.Close()

	// 1. Active connection scenario: keep sending data every 50ms for 500ms (> 200ms StreamTimeout)
	t.Run("ActiveConnectionStaysOpen", func(t *testing.T) {
		proxyURL := strings.TrimPrefix(proxy.URL, "http://")
		conn, err := net.Dial("tcp", proxyURL)
		if err != nil {
			t.Fatalf("failed to dial proxy: %v", err)
		}
		defer conn.Close()

		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", proxyURL)
		conn.Write([]byte(req))

		// Read 101 response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "101") {
			t.Fatalf("failed to receive 101 response: %v", err)
		}

		startTime := time.Now()
		// Send a ping every 50ms for 500ms (total duration 500ms > 200ms streamTimeout)
		for i := 0; i < 10; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("failed to write data at step %d: %v", i, err)
			}
			if _, err := conn.Read(buf); err != nil {
				t.Fatalf("failed to read data at step %d: %v", i, err)
			}
		}

		elapsed := time.Since(startTime)
		if elapsed < 450*time.Millisecond {
			t.Fatalf("expected connection to remain open for > 450ms, elapsed: %v", elapsed)
		}

		// Now stop sending traffic and wait for idle timeout (> 200ms)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected error / EOF after idle timeout, but got none")
		}
	})

	// 2. Idle connection scenario: zero traffic closes cleanly after StreamTimeout
	t.Run("IdleConnectionClosesCleanly", func(t *testing.T) {
		proxyURL := strings.TrimPrefix(proxy.URL, "http://")
		conn, err := net.Dial("tcp", proxyURL)
		if err != nil {
			t.Fatalf("failed to dial proxy: %v", err)
		}
		defer conn.Close()

		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", proxyURL)
		conn.Write([]byte(req))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "101") {
			t.Fatalf("failed to receive 101 response: %v", err)
		}

		start := time.Now()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(buf)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected connection to close due to idle timeout")
		}
		if elapsed < 150*time.Millisecond || elapsed > 1000*time.Millisecond {
			t.Fatalf("expected idle timeout around 200ms, elapsed: %v", elapsed)
		}
	})
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

