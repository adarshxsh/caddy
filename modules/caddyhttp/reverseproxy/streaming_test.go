package reverseproxy

import (
	"bytes"
	"io"
	"net/http"
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

type flushCounterWriter struct {
	bytes.Buffer
	flushes int
	mu      sync.Mutex
}

func (f *flushCounterWriter) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return nil
}

func (f *flushCounterWriter) getFlushes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

func TestH2ReadWriteCloserBufferedFlush(t *testing.T) {
	fc := &flushCounterWriter{}
	latency := 50 * time.Millisecond

	mlw := &maxLatencyWriter{
		dst:     fc,
		flush:   fc.Flush,
		latency: latency,
		logger:  caddy.Log(),
	}

	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		flusher:    mlw,
	}

	_, err := rwc.Write([]byte("hello "))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := fc.getFlushes(); got != 0 {
		t.Fatalf("expected 0 flushes immediately, got %d", got)
	}

	_, err = rwc.Write([]byte("world"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := fc.getFlushes(); got != 0 {
		t.Fatalf("expected 0 flushes before timer, got %d", got)
	}

	time.Sleep(100 * time.Millisecond)
	if got := fc.getFlushes(); got != 1 {
		t.Fatalf("expected 1 flush after timer, got %d", got)
	}
	if got := fc.String(); got != "hello world" {
		t.Fatalf("expected content %q, got %q", "hello world", got)
	}

	if err := rwc.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestH2ReadWriteCloserExplicitFlush(t *testing.T) {
	fc := &flushCounterWriter{}
	latency := 1 * time.Second

	mlw := &maxLatencyWriter{
		dst:     fc,
		flush:   fc.Flush,
		latency: latency,
		logger:  caddy.Log(),
	}

	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		flusher:    mlw,
	}

	_, err := rwc.Write([]byte("explicit flush"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := fc.getFlushes(); got != 0 {
		t.Fatalf("expected 0 flushes before explicit flush, got %d", got)
	}

	if err := rwc.Flush(); err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}
	if got := fc.getFlushes(); got != 1 {
		t.Fatalf("expected 1 flush after explicit Flush(), got %d", got)
	}
}

func TestH2ReadWriteCloserImmediateFlushWhenNegativeLatency(t *testing.T) {
	fc := &flushCounterWriter{}

	mlw := &maxLatencyWriter{
		dst:     fc,
		flush:   fc.Flush,
		latency: -1,
		logger:  caddy.Log(),
	}

	rwc := h2ReadWriteCloser{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		flusher:    mlw,
	}

	_, err := rwc.Write([]byte("immediate"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := fc.getFlushes(); got != 1 {
		t.Fatalf("expected 1 immediate flush, got %d", got)
	}
}

func TestFlushIntervalBidirectionalStream(t *testing.T) {
	h := Handler{
		FlushInterval: 0,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.ProtoMajor = 2

	res := &http.Response{
		ProtoMajor:    2,
		ContentLength: -1,
		Header:        make(http.Header),
	}

	// Unconfigured FlushInterval should return defaultFlushInterval (250us)
	if got := h.flushInterval(req, res); got != defaultFlushInterval {
		t.Fatalf("expected defaultFlushInterval %v, got %v", defaultFlushInterval, got)
	}

	// Configured FlushInterval should be respected
	h.FlushInterval = caddy.Duration(10 * time.Millisecond)
	if got := h.flushInterval(req, res); got != 10*time.Millisecond {
		t.Fatalf("expected configured FlushInterval 10ms, got %v", got)
	}

	// Explicit negative FlushInterval should be respected
	h.FlushInterval = caddy.Duration(-1)
	if got := h.flushInterval(req, res); got != -1 {
		t.Fatalf("expected explicit negative FlushInterval -1, got %v", got)
	}
}
