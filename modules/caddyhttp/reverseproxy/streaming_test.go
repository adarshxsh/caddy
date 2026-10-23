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
	"go.uber.org/zap"
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

type mockFlushWriter struct {
	bytes.Buffer
	mu         sync.Mutex
	flushCount int
}

func (m *mockFlushWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCount++
	return nil
}

func (m *mockFlushWriter) FlushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushCount
}

func TestMaxLatencyWriter_InitialWriteFlush(t *testing.T) {
	fw := &mockFlushWriter{}
	latency := 500 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:               fw,
		flush:             fw.Flush,
		latency:           latency,
		logger:            zap.NewNop(),
		firstFlushPending: true,
	}
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)
	defer mlw.stop()

	if fw.FlushCount() != 0 {
		t.Fatalf("expected 0 flushes before write, got %d", fw.FlushCount())
	}

	n, err := mlw.Write([]byte("initial chunk"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 13 {
		t.Fatalf("expected 13 bytes written, got %d", n)
	}

	if fw.FlushCount() != 1 {
		t.Fatalf("expected 1 flush immediately on initial write, got %d", fw.FlushCount())
	}
	if fw.String() != "initial chunk" {
		t.Fatalf("expected payload 'initial chunk', got %q", fw.String())
	}
}

func TestMaxLatencyWriter_TimerResetOnSubsequentWrites(t *testing.T) {
	fw := &mockFlushWriter{}
	latency := 50 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:               fw,
		flush:             fw.Flush,
		latency:           latency,
		logger:            zap.NewNop(),
		firstFlushPending: true,
	}
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)
	defer mlw.stop()

	// Initial write flushes immediately and stops initial timer
	_, _ = mlw.Write([]byte("chunk1"))
	initialFlushes := fw.FlushCount()

	// Second write starts active timer
	_, _ = mlw.Write([]byte("chunk2"))
	time.Sleep(20 * time.Millisecond)

	// Third write occurs before timer expires -> resets timer
	_, _ = mlw.Write([]byte("chunk3"))

	// Sleep 20ms: total 40ms since chunk2, but only 20ms since chunk3.
	// Since original 50ms timer was reset at 20ms, it shouldn't fire at 40ms.
	time.Sleep(20 * time.Millisecond)
	if fw.FlushCount() != initialFlushes {
		t.Fatalf("expected flush timer to have been reset, but got early flush count %d", fw.FlushCount())
	}

	// Sleep another 40ms to let reset timer expire (50ms after chunk3 write)
	time.Sleep(40 * time.Millisecond)
	if fw.FlushCount() != initialFlushes+1 {
		t.Fatalf("expected flush count %d after reset timer expired, got %d", initialFlushes+1, fw.FlushCount())
	}
}

func TestMaxLatencyWriter_IdleFlush(t *testing.T) {
	fw := &mockFlushWriter{}
	latency := 30 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:               fw,
		flush:             fw.Flush,
		latency:           latency,
		logger:            zap.NewNop(),
		firstFlushPending: true,
	}
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)
	defer mlw.stop()

	if fw.FlushCount() != 0 {
		t.Fatalf("expected 0 flushes before timer, got %d", fw.FlushCount())
	}

	time.Sleep(60 * time.Millisecond)
	if fw.FlushCount() != 1 {
		t.Fatalf("expected 1 idle flush after timer expired, got %d", fw.FlushCount())
	}
}

func TestMaxLatencyWriter_ConcurrentWritesRace(t *testing.T) {
	fw := &mockFlushWriter{}
	latency := 10 * time.Millisecond
	mlw := &maxLatencyWriter{
		dst:               fw,
		flush:             fw.Flush,
		latency:           latency,
		logger:            zap.NewNop(),
		firstFlushPending: true,
	}
	mlw.t = time.AfterFunc(latency, mlw.delayedFlush)
	defer mlw.stop()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = mlw.Write([]byte("a"))
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
}
