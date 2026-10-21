package reverseproxy

import (
	"bytes"
	"context"
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

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

type mockDeadlineReadWriteCloser struct {
	io.Reader
	buf          bytes.Buffer
	mu           sync.Mutex
	deadlines    []time.Time
	writeErr     error
	blockOnWrite bool
}

func (m *mockDeadlineReadWriteCloser) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deadlines = append(m.deadlines, t)
	return nil
}

func (m *mockDeadlineReadWriteCloser) Write(p []byte) (int, error) {
	m.mu.Lock()
	if m.writeErr != nil {
		err := m.writeErr
		m.mu.Unlock()
		return 0, err
	}
	m.mu.Unlock()

	if m.blockOnWrite {
		return 0, context.DeadlineExceeded
	}
	return m.buf.Write(p)
}

func (m *mockDeadlineReadWriteCloser) Close() error { return nil }

func TestSwitchProtocolCopierWriteDeadline(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	userConn := &mockDeadlineReadWriteCloser{
		Reader: strings.NewReader(""),
	}
	backendConn := &mockDeadlineReadWriteCloser{
		Reader: strings.NewReader("hello from backend"),
	}

	copier := switchProtocolCopier{
		user:         userConn,
		backend:      backendConn,
		wg:           &wg,
		writeTimeout: 5 * time.Second,
	}

	wg.Add(1)
	go copier.copyFromBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyFromBackend() unexpected error = %v", err)
	}

	if got := userConn.buf.String(); got != "hello from backend" {
		t.Fatalf("user received = %q, want %q", got, "hello from backend")
	}

	userConn.mu.Lock()
	defer userConn.mu.Unlock()
	if len(userConn.deadlines) == 0 {
		t.Fatalf("expected SetWriteDeadline to be called, got 0 calls")
	}
	// Verify deadline set was non-zero
	if userConn.deadlines[0].IsZero() {
		t.Fatalf("expected non-zero write deadline, got zero")
	}
}

func TestSwitchProtocolCopierStalledWriteTimeout(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 1)

	userConn := &mockDeadlineReadWriteCloser{
		Reader:       strings.NewReader(""),
		blockOnWrite: true,
	}
	backendConn := &mockDeadlineReadWriteCloser{
		Reader: strings.NewReader("data stream payload"),
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

	err := <-errc
	if err == nil {
		t.Fatalf("expected error from stalled write, got nil")
	}
}

func TestCaddyfileStreamWriteTimeout(t *testing.T) {
	input := `reverse_proxy localhost:8080 {
		stream_write_timeout 10s
	}`
	d := caddyfile.NewTestDispenser(input)
	h := new(Handler)
	err := h.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if time.Duration(h.StreamWriteTimeout) != 10*time.Second {
		t.Fatalf("expected StreamWriteTimeout = 10s, got %v", h.StreamWriteTimeout)
	}
}

