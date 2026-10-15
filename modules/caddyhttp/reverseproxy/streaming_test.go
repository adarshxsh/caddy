package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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

func TestNewLockedReadWriteCloser(t *testing.T) {
	if got := newLockedReadWriteCloser(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	base := nopReadWriteCloser{Reader: strings.NewReader(""), Writer: &bytes.Buffer{}}
	wrapped := newLockedReadWriteCloser(base)
	if wrapped == nil {
		t.Fatalf("expected non-nil wrapped ReadWriteCloser")
	}

	// Re-wrapping should return the same instance
	rewrapped := newLockedReadWriteCloser(wrapped)
	if rewrapped != wrapped {
		t.Fatalf("expected rewrapped instance to equal wrapped instance")
	}
}

func TestLockedReadWriteCloserConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	var bufMu sync.Mutex

	// Underlying writer guarded by bufMu so byte buffer operations are safe,
	// while lockedReadWriteCloser serializes writes from callers.
	safeWriter := &safeTestWriter{buf: &buf, mu: &bufMu}
	rwc := nopReadWriteCloser{Reader: strings.NewReader(""), Writer: safeWriter}
	locked := newLockedReadWriteCloser(rwc)

	const goroutines = 10
	const writesPerGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			payload := []byte("0123456789abcdef")
			for j := 0; j < writesPerGoroutine; j++ {
				n, err := locked.Write(payload)
				if err != nil {
					t.Errorf("goroutine %d write error: %v", id, err)
					return
				}
				if n != len(payload) {
					t.Errorf("goroutine %d short write: got %d, want %d", id, n, len(payload))
					return
				}
			}
		}(i)
	}

	wg.Wait()

	bufMu.Lock()
	totalBytes := buf.Len()
	bufMu.Unlock()

	expectedBytes := goroutines * writesPerGoroutine * 16
	if totalBytes != expectedBytes {
		t.Fatalf("total bytes written = %d, want %d", totalBytes, expectedBytes)
	}
}

func TestLockedReadWriteCloserWriteCloseControlAndCopy(t *testing.T) {
	pr, pw := io.Pipe()
	rwc := &pipeRWC{PipeReader: pr, PipeWriter: pw}
	locked := newLockedReadWriteCloser(rwc)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Continuous streaming write (simulating io.CopyBuffer)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			chunk := []byte("stream-data-chunk-")
			_, _ = locked.Write(chunk)
		}
	}()

	// Goroutine 2: Close control write (simulating writeCloseControl)
	go func() {
		defer wg.Done()
		_ = writeCloseControl(locked, false)
	}()

	// Goroutine to drain pipe reader so writes don't block forever
	doneDrain := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, pr)
		close(doneDrain)
	}()

	wg.Wait()
	_ = pw.Close()
	<-doneDrain
}

type safeTestWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (s *safeTestWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

type pipeRWC struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p *pipeRWC) Read(b []byte) (int, error) {
	return p.PipeReader.Read(b)
}

func (p *pipeRWC) Write(b []byte) (int, error) {
	return p.PipeWriter.Write(b)
}

func (p *pipeRWC) Close() error {
	_ = p.PipeReader.Close()
	return p.PipeWriter.Close()
}
