package reverseproxy

import (
	"bytes"
	"io"
	"net"
	"net/http/httptest"
	"runtime"
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

type mockDeadlineConn struct {
	nopReadWriteCloser
	deadlineSet      bool
	readDeadlineSet  bool
	writeDeadlineSet bool
	lastTime         time.Time
}

func (m *mockDeadlineConn) SetDeadline(t time.Time) error {
	m.deadlineSet = true
	m.lastTime = t
	return nil
}

func (m *mockDeadlineConn) SetReadDeadline(t time.Time) error {
	m.readDeadlineSet = true
	m.lastTime = t
	return nil
}

func (m *mockDeadlineConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadlineSet = true
	m.lastTime = t
	return nil
}

type wrappedConn struct {
	inner io.ReadWriteCloser
}

func (w wrappedConn) Read(p []byte) (n int, err error)  { return w.inner.Read(p) }
func (w wrappedConn) Write(p []byte) (n int, err error) { return w.inner.Write(p) }
func (w wrappedConn) Close() error                      { return w.inner.Close() }
func (w wrappedConn) Unwrap() io.ReadWriteCloser        { return w.inner }

func TestExpireDeadlines(t *testing.T) {
	m := &mockDeadlineConn{}
	expireDeadlines(m)
	if !m.deadlineSet || !m.readDeadlineSet || !m.writeDeadlineSet {
		t.Errorf("expireDeadlines did not call all deadline methods, got deadlineSet=%v readDeadlineSet=%v writeDeadlineSet=%v",
			m.deadlineSet, m.readDeadlineSet, m.writeDeadlineSet)
	}
	if m.lastTime != time.Unix(0, 1) {
		t.Errorf("expireDeadlines set time = %v, want past time %v", m.lastTime, time.Unix(0, 1))
	}

	m2 := &mockDeadlineConn{}
	w := wrappedConn{inner: m2}
	expireDeadlines(w)
	if !m2.deadlineSet || !m2.readDeadlineSet || !m2.writeDeadlineSet {
		t.Errorf("expireDeadlines on wrapped conn did not trigger inner deadlines")
	}
}

func TestH2ReadWriteCloserDeadlines(t *testing.T) {
	m := &mockDeadlineConn{}
	rec := httptest.NewRecorder()
	h2rwc := h2ReadWriteCloser{
		ReadCloser:     m,
		ResponseWriter: rec,
	}

	err := h2rwc.SetDeadline(time.Unix(0, 1))
	if err != nil {
		t.Errorf("unexpected error setting deadline on h2ReadWriteCloser: %v", err)
	}
	if !m.deadlineSet && !m.readDeadlineSet {
		t.Errorf("SetDeadline failed to propagate to ReadCloser")
	}
}

func TestStalledCopierUnblocksOnDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	// Endless reader source for user
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: pr, Writer: io.Discard},
		backend:    c1,
		wg:         &wg,
		bufferSize: 1024,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)

	// Send data into pr so io.CopyBuffer attempts to write to c1 (net.Pipe).
	// Because nobody is reading from c2, the write to net.Pipe will block!
	go func() {
		hugeData := make([]byte, 65536)
		for i := 0; i < 100; i++ {
			_, err := pw.Write(hugeData)
			if err != nil {
				return
			}
		}
	}()

	// Give time for io.CopyBuffer to start and block on net.Pipe write
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Expire deadlines on c1
	expireDeadlines(c1)

	select {
	case <-done:
		// Successfully unblocked and WG done!
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("copier goroutine did not exit within 50ms after expireDeadlines")
	}

	select {
	case err := <-errc:
		if err == nil {
			t.Errorf("expected error from blocked copier, got nil")
		}
	default:
		t.Errorf("expected error pushed to errc")
	}
}

func TestNoGoroutineLeakOnBackpressure(t *testing.T) {
	baseline := runtime.NumGoroutine()

	for i := 0; i < 5; i++ {
		c1, c2 := net.Pipe()
		var wg sync.WaitGroup
		errc := make(chan error, 2)

		pr, pw := io.Pipe()

		copier := switchProtocolCopier{
			user:       nopReadWriteCloser{Reader: pr, Writer: io.Discard},
			backend:    c1,
			wg:         &wg,
			bufferSize: 1024,
		}

		wg.Add(2)
		go copier.copyToBackend(errc)
		go copier.copyFromBackend(errc)

		// Cause writes to block
		go func() {
			_, _ = pw.Write([]byte("some data to block"))
		}()

		time.Sleep(10 * time.Millisecond)

		expireDeadlines(c1)
		expireDeadlines(c2)
		_ = pr.Close()
		_ = pw.Close()
		_ = c1.Close()
		_ = c2.Close()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: copier goroutines leaked", i)
		}
	}

	// Wait briefly for goroutine runtime cleanup
	time.Sleep(50 * time.Millisecond)
	leaked := runtime.NumGoroutine() - baseline
	if leaked > 2 { // allow minor background runtime variance
		t.Errorf("detected goroutine leaks: before=%d, after=%d, diff=%d", baseline, runtime.NumGoroutine(), leaked)
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
