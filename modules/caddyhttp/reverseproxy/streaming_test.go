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
	tests := []struct {
		name          string
		flushInterval caddy.Duration
		req           *http.Request
		res           *http.Response
		want          time.Duration
	}{
		{
			name:          "unset Content-Length respects positive flush_interval",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{},
			},
			want: 250 * time.Millisecond,
		},
		{
			name:          "unset Content-Length with zero flush_interval returns 0",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{},
			},
			want: 0,
		},
		{
			name:          "unset Content-Length with explicit negative flush_interval returns -1",
			flushInterval: caddy.Duration(-1),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{},
			},
			want: -1,
		},
		{
			name:          "known Content-Length respects positive flush_interval",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: 100,
				Header:        http.Header{},
			},
			want: 250 * time.Millisecond,
		},
		{
			name:          "text/event-stream overrides flush_interval to -1",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			},
			want: -1,
		},
		{
			name:          "text/event-stream with charset overrides flush_interval to -1",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
			},
			want: -1,
		},
		{
			name:          "h2 bidirectional stream overrides flush_interval to -1",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req: &http.Request{
				ProtoMajor: 2,
				Header:     http.Header{"Accept-Encoding": []string{"identity"}},
			},
			res: &http.Response{
				ProtoMajor:    2,
				ContentLength: -1,
				Header:        http.Header{},
			},
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{
				FlushInterval: tt.flushInterval,
			}
			if got := h.flushInterval(tt.req, tt.res); got != tt.want {
				t.Errorf("flushInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

type flushCountingRecorder struct {
	*httptest.ResponseRecorder
	flushCount int
	mu         sync.Mutex
}

func (f *flushCountingRecorder) Flush() {
	f.mu.Lock()
	f.flushCount++
	f.mu.Unlock()
	f.ResponseRecorder.Flush()
}

func (f *flushCountingRecorder) getFlushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushCount
}

func TestCopyResponseFlushInterval(t *testing.T) {
	h := Handler{}

	t.Run("immediate flushing on negative interval", func(t *testing.T) {
		rec := &flushCountingRecorder{ResponseRecorder: httptest.NewRecorder()}
		pr, pw := io.Pipe()

		go func() {
			pw.Write([]byte("chunk1"))
			time.Sleep(10 * time.Millisecond)
			pw.Write([]byte("chunk2"))
			time.Sleep(10 * time.Millisecond)
			pw.Write([]byte("chunk3"))
			pw.Close()
		}()

		err := h.copyResponse(rec, pr, -1, caddy.Log())
		if err != nil {
			t.Fatalf("copyResponse error: %v", err)
		}

		if got := rec.getFlushCount(); got < 3 {
			t.Errorf("flush count = %d, want >= 3 for immediate flushing", got)
		}
		if got := rec.Body.String(); got != "chunk1chunk2chunk3" {
			t.Errorf("body = %q, want %q", got, "chunk1chunk2chunk3")
		}
	})

	t.Run("batched flushing on positive interval", func(t *testing.T) {
		rec := &flushCountingRecorder{ResponseRecorder: httptest.NewRecorder()}
		pr, pw := io.Pipe()

		go func() {
			// Write multiple small chunks rapidly without delay
			pw.Write([]byte("chunk1"))
			pw.Write([]byte("chunk2"))
			pw.Write([]byte("chunk3"))
			pw.Close()
		}()

		err := h.copyResponse(rec, pr, 200*time.Millisecond, caddy.Log())
		if err != nil {
			t.Fatalf("copyResponse error: %v", err)
		}

		if got := rec.Body.String(); got != "chunk1chunk2chunk3" {
			t.Errorf("body = %q, want %q", got, "chunk1chunk2chunk3")
		}
	})
}
