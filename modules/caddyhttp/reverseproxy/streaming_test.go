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

type mockRWC struct {
	readData  []byte
	writeData []byte
}

func (m *mockRWC) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(p, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockRWC) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	m.writeData = append(m.writeData, p...)
	return len(p), nil
}

func (m *mockRWC) Close() error { return nil }

func TestActivityRWC(t *testing.T) {
	var activityCount int
	onActivity := func() {
		activityCount++
	}

	mockConn := &mockRWC{readData: []byte("world")}

	arwc := activityRWC{
		ReadWriteCloser: mockConn,
		onActivity:      onActivity,
	}

	// Write non-zero bytes
	n, err := arwc.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write error: %v, n: %d", err, n)
	}
	if activityCount != 1 {
		t.Fatalf("Expected activityCount 1 after Write, got %d", activityCount)
	}

	// Write zero bytes
	n, err = arwc.Write([]byte(""))
	if err != nil || n != 0 {
		t.Fatalf("Write empty error: %v, n: %d", err, n)
	}
	if activityCount != 1 {
		t.Fatalf("Expected activityCount 1 after zero-byte Write, got %d", activityCount)
	}

	// Read non-zero bytes
	readBuf := make([]byte, 10)
	n, err = arwc.Read(readBuf)
	if err != nil || n != 5 {
		t.Fatalf("Read error: %v, n: %d", err, n)
	}
	if activityCount != 2 {
		t.Fatalf("Expected activityCount 2 after Read, got %d", activityCount)
	}

	// Read zero bytes
	n, err = arwc.Read([]byte{})
	if err != nil || n != 0 {
		t.Fatalf("Read empty error: %v, n: %d", err, n)
	}
	if activityCount != 2 {
		t.Fatalf("Expected activityCount 2 after zero-byte Read, got %d", activityCount)
	}

	// Read EOF (n == 0)
	n, err = arwc.Read(readBuf)
	if err != io.EOF || n != 0 {
		t.Fatalf("Expected EOF and n=0, got err: %v, n: %d", err, n)
	}
	if activityCount != 2 {
		t.Fatalf("Expected activityCount 2 after EOF Read, got %d", activityCount)
	}
}

type mockHijacker struct {
	httptest.ResponseRecorder
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.brw, nil
}

func TestStreamTimeoutActivityRefreshed(t *testing.T) {
	// Subtest 1: Idle connection times out
	t.Run("Idle stream timeout", func(t *testing.T) {
		clientFront, serverFront := net.Pipe()
		clientBack, serverBack := net.Pipe()

		defer clientFront.Close()
		defer serverFront.Close()
		defer clientBack.Close()
		defer serverBack.Close()

		h := Handler{
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
			Body:       serverBack,
		}
		res.Header.Set("Connection", "Upgrade")
		res.Header.Set("Upgrade", "websocket")

		rw := &mockHijacker{
			conn: serverFront,
			brw:  bufio.NewReadWriter(bufio.NewReader(serverFront), bufio.NewWriter(serverFront)),
		}

		var wg sync.WaitGroup
		start := time.Now()
		h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)

		elapsed := time.Since(start)

		if elapsed < 80*time.Millisecond {
			t.Fatalf("Expected timeout of at least 100ms, timed out in %v", elapsed)
		}
	})

	// Subtest 2: Active connection sending data resets timer and stays open past timeout
	t.Run("Active stream refreshes timeout", func(t *testing.T) {
		clientFront, serverFront := net.Pipe()
		clientBack, serverBack := net.Pipe()

		h := Handler{
			StreamTimeout: caddy.Duration(150 * time.Millisecond),
			connections:   make(map[io.ReadWriteCloser]openConnection),
			connectionsMu: new(sync.Mutex),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		res := &http.Response{
			StatusCode: 101,
			Header:     make(http.Header),
			Body:       serverBack,
		}
		res.Header.Set("Connection", "Upgrade")
		res.Header.Set("Upgrade", "websocket")

		rw := &mockHijacker{
			conn: serverFront,
			brw:  bufio.NewReadWriter(bufio.NewReader(serverFront), bufio.NewWriter(serverFront)),
		}

		var wg sync.WaitGroup
		done := make(chan struct{})
		go func() {
			h.handleUpgradeResponse(zap.NewNop(), &wg, rw, req, res)
			close(done)
		}()

		// Start backend echo loop in separate goroutine
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := clientBack.Read(buf)
				if err != nil {
					return
				}
				_, err = clientBack.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}()

		// Send traffic across clientFront <-> clientBack every 40ms for 350ms total
		// (350ms > 150ms timeout)
		stopTraffic := make(chan struct{})
		go func() {
			ticker := time.NewTicker(40 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					_, err := clientFront.Write([]byte("ping"))
					if err != nil {
						return
					}
					buf := make([]byte, 1024)
					_, err = clientFront.Read(buf)
					if err != nil {
						return
					}
				case <-stopTraffic:
					return
				}
			}
		}()

		// Wait 350ms. Connection should still be active because traffic was sent every 40ms.
		time.Sleep(350 * time.Millisecond)

		select {
		case <-done:
			t.Fatalf("Connection timed out prematurely despite active traffic!")
		default:
			// Connection is still alive, as expected!
		}

		// Stop traffic and measure time until timeout
		lastTrafficTime := time.Now()
		close(stopTraffic)

		<-done
		timeSinceLastTraffic := time.Since(lastTrafficTime)

		if timeSinceLastTraffic < 100*time.Millisecond {
			t.Fatalf("Expected timeout after inactivity of ~150ms, but closed in %v", timeSinceLastTraffic)
		}

		_ = clientFront.Close()
		_ = serverFront.Close()
		_ = clientBack.Close()
		_ = serverBack.Close()
	})
}
