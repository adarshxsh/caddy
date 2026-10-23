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
			name:          "unset content length with positive flush interval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           &http.Request{},
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			want:          100 * time.Millisecond,
		},
		{
			name:          "unset content length with zero flush interval (unconfigured)",
			flushInterval: 0,
			req:           &http.Request{},
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			want:          -1,
		},
		{
			name:          "unset content length with negative flush interval",
			flushInterval: caddy.Duration(-1),
			req:           &http.Request{},
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			want:          -1,
		},
		{
			name:          "text/event-stream with positive flush interval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           &http.Request{},
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			},
			want: -1,
		},
		{
			name:          "text/event-stream with charset and positive flush interval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           &http.Request{},
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
			},
			want: -1,
		},
		{
			name:          "text/event-stream with zero flush interval",
			flushInterval: 0,
			req:           &http.Request{},
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			},
			want: -1,
		},
		{
			name:          "HTTP/2 bidirectional stream with positive flush interval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req: &http.Request{
				ProtoMajor: 2,
				Header:     make(http.Header),
			},
			res: &http.Response{
				ProtoMajor:    2,
				ContentLength: -1,
				Header:        make(http.Header),
			},
			want: -1,
		},
		{
			name:          "HTTP/2 bidirectional stream with zero flush interval",
			flushInterval: 0,
			req: &http.Request{
				ProtoMajor: 2,
				Header:     make(http.Header),
			},
			res: &http.Response{
				ProtoMajor:    2,
				ContentLength: -1,
				Header:        make(http.Header),
			},
			want: -1,
		},
		{
			name:          "known content length with positive flush interval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           &http.Request{},
			res:           &http.Response{ContentLength: 500, Header: make(http.Header)},
			want:          100 * time.Millisecond,
		},
		{
			name:          "known content length with zero flush interval",
			flushInterval: 0,
			req:           &http.Request{},
			res:           &http.Response{ContentLength: 500, Header: make(http.Header)},
			want:          0,
		},
		{
			name:          "known content length with negative flush interval",
			flushInterval: caddy.Duration(-1),
			req:           &http.Request{},
			res:           &http.Response{ContentLength: 500, Header: make(http.Header)},
			want:          -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{FlushInterval: tt.flushInterval}
			got := h.flushInterval(tt.req, tt.res)
			if got != tt.want {
				t.Errorf("flushInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}
