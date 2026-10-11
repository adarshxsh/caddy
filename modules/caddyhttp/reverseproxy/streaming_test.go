package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestMaxLatencyWriter_HeaderFlush_NoBodyWrites(t *testing.T) {
	var flushCount int32
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:     dst,
		flush:   func() error { atomic.AddInt32(&flushCount, 1); return nil },
		latency: 30 * time.Millisecond,
		logger:  logger,
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 0 {
		t.Fatalf("expected 0 flushes at 10ms, got %d", atomic.LoadInt32(&flushCount))
	}

	time.Sleep(35 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 1 {
		t.Fatalf("expected 1 flush after latency expired, got %d", atomic.LoadInt32(&flushCount))
	}
}

func TestMaxLatencyWriter_FirstWrite_DisarmsHeaderTimer(t *testing.T) {
	var flushCount int32
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:         dst,
		flush:       func() error { atomic.AddInt32(&flushCount, 1); return nil },
		latency:     50 * time.Millisecond,
		minFlushGap: 20 * time.Millisecond,
		logger:      logger,
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// First body write arrives at 10ms
	time.Sleep(10 * time.Millisecond)
	_, err := mlw.Write([]byte("chunk1"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	// At 25ms (15ms after write, 25ms overall), minFlushGap (20ms) hasn't expired yet
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 0 {
		t.Fatalf("expected 0 flushes before minFlushGap, got %d", atomic.LoadInt32(&flushCount))
	}

	// At 40ms after write (50ms overall), body flush should have fired once
	time.Sleep(25 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 1 {
		t.Fatalf("expected 1 flush for body write, got %d", atomic.LoadInt32(&flushCount))
	}

	// Wait past initial 50ms header latency to ensure header timer was disarmed and doesn't double-flush
	time.Sleep(30 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 1 {
		t.Fatalf("expected header timer was disarmed (total 1 flush), got %d", atomic.LoadInt32(&flushCount))
	}
}

func TestMaxLatencyWriter_NextWrites_ResetTimerWithMinFlushGap(t *testing.T) {
	var flushCount int32
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:         dst,
		flush:       func() error { atomic.AddInt32(&flushCount, 1); return nil },
		latency:     100 * time.Millisecond,
		minFlushGap: 30 * time.Millisecond,
		logger:      logger,
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// First write at t=0
	mlw.Write([]byte("a")) // body flush timer set to minFlushGap (30ms)

	// Second write at t=15ms (within active window)
	time.Sleep(15 * time.Millisecond)
	mlw.Write([]byte("b")) // timer reset to minFlushGap (30ms from now => t=45ms)

	// Check at t=35ms (20ms after second write): flush should NOT have happened yet
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 0 {
		t.Fatalf("expected 0 flushes at t=35ms, got %d", atomic.LoadInt32(&flushCount))
	}

	// Check at t=55ms (40ms after second write): flush SHOULD have happened
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&flushCount) != 1 {
		t.Fatalf("expected 1 flush at t=55ms, got %d", atomic.LoadInt32(&flushCount))
	}
}

func TestMaxLatencyWriter_NextWrites_CappedByMaxLatency(t *testing.T) {
	var flushCount int32
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:         dst,
		flush:       func() error { atomic.AddInt32(&flushCount, 1); return nil },
		latency:     50 * time.Millisecond,
		minFlushGap: 30 * time.Millisecond,
		logger:      logger,
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// Write continuously every 10ms
	for i := 0; i < 8; i++ {
		mlw.Write([]byte("x"))
		time.Sleep(10 * time.Millisecond)
	}

	// Total elapsed time = 80ms.
	// Since latency cap is 50ms, flush must have occurred around 50ms from first write.
	if atomic.LoadInt32(&flushCount) < 1 {
		t.Fatalf("expected at least 1 flush capped by max latency, got %d", atomic.LoadInt32(&flushCount))
	}
}

func TestMaxLatencyWriter_ZeroAllocationsOnWrite(t *testing.T) {
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:         dst,
		flush:       func() error { return nil },
		latency:     10 * time.Second,
		minFlushGap: 5 * time.Second,
		logger:      logger,
	}
	defer mlw.stop()

	mlw.startHeaderTimer()

	// First write allocates timer
	mlw.Write([]byte("first"))

	buf := []byte("hello")
	allocs := testing.AllocsPerRun(10, func() {
		mlw.Write(buf)
	})

	if allocs > 0 {
		t.Fatalf("expected 0 allocations per Write call, got %f", allocs)
	}
}

func TestMaxLatencyWriter_ConcurrentRace(t *testing.T) {
	dst := new(bytes.Buffer)
	logger := zap.NewNop()

	mlw := &maxLatencyWriter{
		dst:         dst,
		flush:       func() error { return nil },
		latency:     5 * time.Millisecond,
		minFlushGap: 2 * time.Millisecond,
		logger:      logger,
	}
	mlw.startHeaderTimer()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				mlw.Write([]byte("data"))
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}

	wg.Wait()
	mlw.stop()
}

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
