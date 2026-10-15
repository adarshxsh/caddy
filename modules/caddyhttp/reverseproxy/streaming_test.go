package reverseproxy

import (
	"bytes"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

type mockKeepAliveConn struct {
	nopReadWriteCloser
	called bool
	cfg    net.KeepAliveConfig
}

func (m *mockKeepAliveConn) SetKeepAliveConfig(cfg net.KeepAliveConfig) error {
	m.called = true
	m.cfg = cfg
	return nil
}

func TestEnableTCPKeepAlive(t *testing.T) {
	conn := &mockKeepAliveConn{}
	enableTCPKeepAlive(conn)

	if !conn.called {
		t.Fatalf("expected SetKeepAliveConfig to be called on mock connection")
	}
	if !conn.cfg.Enable {
		t.Fatalf("expected KeepAliveConfig.Enable to be true, got false")
	}
	if conn.cfg.Idle != 15*time.Second || conn.cfg.Interval != 15*time.Second {
		t.Fatalf("unexpected KeepAliveConfig durations: idle=%v, interval=%v", conn.cfg.Idle, conn.cfg.Interval)
	}
}

func TestWritePingControl(t *testing.T) {
	t.Run("client unmasked ping", func(t *testing.T) {
		var buf bytes.Buffer
		err := writePingControl(&buf, false)
		if err != nil {
			t.Fatalf("unexpected error writing client ping: %v", err)
		}
		got := buf.Bytes()
		expected := []byte{0x89, 0x00}
		if !bytes.Equal(got, expected) {
			t.Fatalf("got %x, want %x", got, expected)
		}
	})

	t.Run("backend masked ping", func(t *testing.T) {
		var buf bytes.Buffer
		err := writePingControl(&buf, true)
		if err != nil {
			t.Fatalf("unexpected error writing backend ping: %v", err)
		}
		got := buf.Bytes()
		if len(got) != 6 {
			t.Fatalf("expected length 6 for masked ping, got %d", len(got))
		}
		if got[0] != 0x89 {
			t.Fatalf("expected opcode 0x89, got 0x%x", got[0])
		}
		if got[1] != 0x80 {
			t.Fatalf("expected byte1 0x80 (masked length 0), got 0x%x", got[1])
		}
	})
}

func TestConcurrentDataAndPingWrites(t *testing.T) {
	var buf bytes.Buffer
	mw := &mutexWriter{w: &buf}

	var wg sync.WaitGroup
	// 10 concurrent data writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = mw.Write([]byte("data payload chunk "))
			}
		}()
	}

	// 5 concurrent ping writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(isClient bool) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = writePingControl(mw, isClient)
			}
		}(i%2 == 0)
	}

	wg.Wait()
	if buf.Len() == 0 {
		t.Fatalf("expected non-empty output buffer")
	}
}

func TestCaddyfileWebSocketKeepAliveParsing(t *testing.T) {
	input := `reverse_proxy localhost:8080 {
		websocket_keepalive 10s
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	err := h.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if time.Duration(h.WebSocketKeepAlive) != 10*time.Second {
		t.Fatalf("expected WebSocketKeepAlive to be 10s, got %v", h.WebSocketKeepAlive)
	}
}

