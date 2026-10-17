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

func TestFlushInterval(t *testing.T) {
	for i, tc := range []struct {
		name          string
		flushInterval caddy.Duration
		req           *http.Request
		res           *http.Response
		expect        time.Duration
	}{
		{
			name:          "Chunked response with positive FlushInterval",
			flushInterval: caddy.Duration(50 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: 50 * time.Millisecond,
		},
		{
			name:          "Chunked response with zero FlushInterval (unconfigured default)",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: -1,
		},
		{
			name:          "SSE text/event-stream response bypasses FlushInterval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			},
			expect: -1,
		},
		{
			name:          "SSE text/event-stream with parameters bypasses FlushInterval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: 100,
				Header:        http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
			},
			expect: -1,
		},
		{
			name:          "HTTP/2 bidirectional stream bypasses FlushInterval",
			flushInterval: caddy.Duration(200 * time.Millisecond),
			req: &http.Request{
				ProtoMajor: 2,
				Header:     http.Header{"Accept-Encoding": []string{"identity"}},
			},
			res: &http.Response{
				ProtoMajor:    2,
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: -1,
		},
		{
			name:          "Known Content-Length with positive FlushInterval",
			flushInterval: caddy.Duration(50 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: 500,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: 50 * time.Millisecond,
		},
		{
			name:          "Known Content-Length with zero FlushInterval",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: 500,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: 0,
		},
		{
			name:          "Negative FlushInterval disables buffering",
			flushInterval: caddy.Duration(-1),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				StatusCode:    200,
				ContentLength: 500,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
			},
			expect: -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := Handler{FlushInterval: tc.flushInterval}
			got := h.flushInterval(tc.req, tc.res)
			if got != tc.expect {
				t.Errorf("test %d (%s): expected %v, got %v", i, tc.name, tc.expect, got)
			}
		})
	}
}

func TestCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{}
	intervals := []time.Duration{
		0,
		-1,
		10 * time.Millisecond,
	}

	for _, interval := range intervals {
		dst := bytes.NewBuffer(nil)
		recorder := httptest.NewRecorder()
		recorder.Body = dst

		data := "hello world streaming data"
		src := bytes.NewBufferString(data)
		err := h.copyResponse(recorder, src, interval, caddy.Log())
		if err != nil {
			t.Fatalf("copyResponse with interval %v failed: %v", interval, err)
		}
		if got := dst.String(); got != data {
			t.Fatalf("got %q, want %q", got, data)
		}
	}
}

type flushTrackerRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
	mu      sync.Mutex
}

func (f *flushTrackerRecorder) Flush() {
	f.mu.Lock()
	f.flushed = true
	f.mu.Unlock()
	f.ResponseRecorder.Flush()
}

func (f *flushTrackerRecorder) isFlushed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushed
}

func TestMaxLatencyWriterChunkedFlush(t *testing.T) {
	h := Handler{FlushInterval: caddy.Duration(10 * time.Millisecond)}

	pr, pw := io.Pipe()
	recorder := &flushTrackerRecorder{ResponseRecorder: httptest.NewRecorder()}

	req := httptest.NewRequest("GET", "/", nil)
	res := &http.Response{
		StatusCode:    200,
		ContentLength: -1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
	}

	interval := h.flushInterval(req, res)
	if interval != 10*time.Millisecond {
		t.Fatalf("expected 10ms flush interval, got %v", interval)
	}

	done := make(chan error)
	go func() {
		done <- h.copyResponse(recorder, pr, interval, caddy.Log())
	}()

	// Write initial chunk
	_, err := pw.Write([]byte("chunk1"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for maxLatencyWriter flush timer to fire (interval is 10ms)
	time.Sleep(30 * time.Millisecond)

	if !recorder.isFlushed() {
		t.Errorf("expected recorder to be flushed after flushInterval")
	}

	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("copyResponse error: %v", err)
	}
}
