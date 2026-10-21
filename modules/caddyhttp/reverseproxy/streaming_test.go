package reverseproxy

import (
	"bytes"
	"io"
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

func TestWritePingControlServer(t *testing.T) {
	var buf bytes.Buffer
	err := writePingControl(&buf, false, []byte("ping"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.Bytes()
	if len(out) != 2+4 {
		t.Fatalf("expected 6 bytes, got %d", len(out))
	}
	if out[0] != 0x89 {
		t.Errorf("byte 0 = 0x%x, want 0x89 (FIN + Ping)", out[0])
	}
	if out[1] != 4 {
		t.Errorf("byte 1 = 0x%x, want 4 (no mask, len 4)", out[1])
	}
	if string(out[2:]) != "ping" {
		t.Errorf("payload = %q, want 'ping'", string(out[2:]))
	}
}

func TestWritePingControlClient(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")
	err := writePingControl(&buf, true, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.Bytes()
	// 2 byte header + 4 byte key + 5 byte payload = 11 bytes
	if len(out) != 2+4+5 {
		t.Fatalf("expected 11 bytes, got %d", len(out))
	}
	if out[0] != 0x89 {
		t.Errorf("byte 0 = 0x%x, want 0x89 (FIN + Ping)", out[0])
	}
	if out[1] != (0x80 | 5) {
		t.Errorf("byte 1 = 0x%x, want 0x85 (Mask + len 5)", out[1])
	}
	var key [4]byte
	copy(key[:], out[2:6])
	maskedPayload := out[6:]
	unmasked := make([]byte, len(maskedPayload))
	copy(unmasked, maskedPayload)
	maskBytes(key, 0, unmasked)
	if string(unmasked) != "hello" {
		t.Errorf("unmasked payload = %q, want 'hello'", string(unmasked))
	}
}

func TestWritePingControlEmptyPayload(t *testing.T) {
	var bufServer bytes.Buffer
	if err := writePingControl(&bufServer, false, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bufServer.Bytes(); len(got) != 2 || got[0] != 0x89 || got[1] != 0 {
		t.Errorf("server empty ping frame = %v, want [0x89, 0x00]", got)
	}

	var bufClient bytes.Buffer
	if err := writePingControl(&bufClient, true, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotClient := bufClient.Bytes()
	if len(gotClient) != 6 {
		t.Fatalf("client empty ping frame len = %d, want 6", len(gotClient))
	}
	if gotClient[0] != 0x89 || gotClient[1] != 0x80 {
		t.Errorf("client header = [0x%x, 0x%x], want [0x89, 0x80]", gotClient[0], gotClient[1])
	}
}

func TestSwitchProtocolCopierKeepalive(t *testing.T) {
	userBuf := new(bytes.Buffer)
	backBuf := new(bytes.Buffer)

	userConn := nopReadWriteCloser{Writer: userBuf}
	backConn := nopReadWriteCloser{Writer: backBuf}

	spc := switchProtocolCopier{
		user:              userConn,
		backend:           backConn,
		userWriter:        newSyncWriter(userConn),
		backendWriter:     newSyncWriter(backConn),
		keepaliveInterval: 20 * time.Millisecond,
		isWebsocket:       true,
	}

	done := make(chan struct{})
	go spc.startKeepalive(done)

	time.Sleep(50 * time.Millisecond)
	close(done)

	if userBuf.Len() == 0 {
		t.Errorf("expected keepalive pings in userBuf, got 0 bytes")
	}
	if backBuf.Len() == 0 {
		t.Errorf("expected keepalive pings in backBuf, got 0 bytes")
	}
}

func TestSwitchProtocolCopierKeepaliveWriteError(t *testing.T) {
	userConn := &closeTrackingConn{Writer: errorWriter{}}
	backConn := &closeTrackingConn{Writer: new(bytes.Buffer)}

	spc := switchProtocolCopier{
		user:              userConn,
		backend:           backConn,
		userWriter:        newSyncWriter(userConn),
		backendWriter:     newSyncWriter(backConn),
		keepaliveInterval: 10 * time.Millisecond,
		isWebsocket:       true,
	}

	done := make(chan struct{})
	go spc.startKeepalive(done)

	time.Sleep(30 * time.Millisecond)

	if !userConn.closed {
		t.Errorf("expected userConn to be closed on keepalive write error")
	}
	if !backConn.closed {
		t.Errorf("expected backConn to be closed on keepalive write error")
	}
}

func TestCaddyfileStreamKeepalive(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{
			input:    "reverse_proxy {\n stream_keepalive_interval 15s \n}",
			expected: 15 * time.Second,
		},
		{
			input:    "reverse_proxy {\n stream_keepalive 10s \n}",
			expected: 10 * time.Second,
		},
		{
			input:    "reverse_proxy {\n websocket_keepalive 5s \n}",
			expected: 5 * time.Second,
		},
	}

	for _, tc := range tests {
		h := &Handler{}
		d := caddyfile.NewTestDispenser(tc.input)
		if err := h.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("UnmarshalCaddyfile failed for input %q: %v", tc.input, err)
		}
		if got := time.Duration(h.StreamKeepaliveInterval); got != tc.expected {
			t.Errorf("for input %q: StreamKeepaliveInterval = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

type errorWriter struct{}

func (errorWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type closeTrackingConn struct {
	io.Reader
	io.Writer
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return nil
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
