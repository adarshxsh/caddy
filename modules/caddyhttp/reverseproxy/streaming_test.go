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

func TestDisableTransportTimeoutsAndDeadlines(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	tcpConn := serverConn.(*net.TCPConn)
	tConn := &tcpRWTimeoutConn{
		TCPConn: tcpConn,
	}
	tConn.readTimeout.Store(int64(50 * time.Millisecond))
	tConn.writeTimeout.Store(int64(50 * time.Millisecond))

	// Disable transport timeouts and deadlines via helper function
	disableTransportTimeoutsAndDeadlines(tConn)

	if readTimeout := time.Duration(tConn.readTimeout.Load()); readTimeout != 0 {
		t.Fatalf("readTimeout = %v, want 0", readTimeout)
	}

	// Read after idle period longer than 50ms
	done := make(chan struct{})
	go func() {
		time.Sleep(80 * time.Millisecond)
		clientConn.Write([]byte("upgraded"))
	}()

	buf := make([]byte, 20)
	go func() {
		n, err := tConn.Read(buf)
		if err != nil {
			t.Errorf("Read error after disableTransportTimeoutsAndDeadlines: %v", err)
		} else if got := string(buf[:n]); got != "upgraded" {
			t.Errorf("got %q, want %q", got, "upgraded")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out waiting for read")
	}
}
