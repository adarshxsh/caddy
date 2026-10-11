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

func TestSwitchProtocolCopierBidirectionalClosure(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := &switchProtocolCopier{
		user:    s1,
		backend: s2,
		wg:      &wg,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	// Close client 1 side to simulate disconnection / stream teardown
	_ = c1.Close()

	// Wait for wg with timeout to ensure both copier routines unblock and complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: both copiers finished
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for copier goroutines to terminate after one side closed")
	}

	_ = c2.Close()
}

type deadlineTrackerConn struct {
	net.Conn
	mu            sync.Mutex
	writeDeadline time.Time
}

func (d *deadlineTrackerConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.writeDeadline = t
	d.mu.Unlock()
	return d.Conn.SetWriteDeadline(t)
}

func TestDeadlineWriterSetsDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tracker := &deadlineTrackerConn{Conn: c1}
	dw := deadlineWriter{
		w:            tracker,
		writeTimeout: 500 * time.Millisecond,
	}

	go func() {
		buf := make([]byte, 10)
		_, _ = c2.Read(buf)
	}()

	start := time.Now()
	n, err := dw.Write([]byte("test"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 4 {
		t.Fatalf("wrote %d bytes, expected 4", n)
	}

	tracker.mu.Lock()
	deadline := tracker.writeDeadline
	tracker.mu.Unlock()

	if deadline.IsZero() {
		t.Fatal("expected write deadline to be set, got zero time")
	}
	if deadline.Before(start.Add(400 * time.Millisecond)) {
		t.Fatalf("write deadline %v set too early relative to start %v", deadline, start)
	}
}

func TestSwitchProtocolCopierWriteDeadlineExceeded(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	spc := &switchProtocolCopier{
		user:         s1,
		backend:      s2,
		wg:           &wg,
		writeTimeout: 50 * time.Millisecond,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	// Write data to c1 (user side) which will copy to s2 (backend side).
	// But no one reads from c2 (backend side end), so write to s2 will block and hit write deadline!
	go func() {
		_, _ = c1.Write([]byte("data that will stall writing to backend"))
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: write deadline expired and unblocked both copiers
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for copier routines to terminate after write deadline")
	}
}

func TestCaddyfileStreamWriteTimeout(t *testing.T) {
	input := `reverse_proxy {
		stream_write_timeout 10s
	}`
	d := caddyfile.NewTestDispenser(input)
	h := &Handler{}
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error parsing stream_write_timeout: %v", err)
	}
	if h.StreamWriteTimeout != caddy.Duration(10*time.Second) {
		t.Fatalf("expected StreamWriteTimeout 10s, got %v", h.StreamWriteTimeout)
	}
}
