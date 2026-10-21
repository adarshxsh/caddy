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
		expected      time.Duration
	}{
		{
			name:          "unconfigured flush interval with unknown content length",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			expected:      -1,
		},
		{
			name:          "configured flush interval with unknown content length",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			expected:      250 * time.Millisecond,
		},
		{
			name:          "configured flush interval with text/event-stream content type",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
			},
			expected: -1,
		},
		{
			name:          "configured flush interval with text/event-stream and charset",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res: &http.Response{
				ContentLength: -1,
				Header:        http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
			},
			expected: -1,
		},
		{
			name:          "unconfigured flush interval with known content length",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res:           &http.Response{ContentLength: 100, Header: make(http.Header)},
			expected:      0,
		},
		{
			name:          "configured flush interval with known content length",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res:           &http.Response{ContentLength: 100, Header: make(http.Header)},
			expected:      250 * time.Millisecond,
		},
		{
			name:          "negative flush interval with unknown content length",
			flushInterval: -1,
			req:           httptest.NewRequest("GET", "http://example.com", nil),
			res:           &http.Response{ContentLength: -1, Header: make(http.Header)},
			expected:      -1,
		},
		{
			name:          "configured flush interval with HTTP/2 bidirectional stream",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			req: &http.Request{
				ProtoMajor: 2,
				Header:     http.Header{"Accept-Encoding": []string{"identity"}},
			},
			res: &http.Response{
				ProtoMajor:    2,
				ContentLength: -1,
				Header:        make(http.Header),
			},
			expected: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Handler{FlushInterval: tc.flushInterval}
			got := h.flushInterval(tc.req, tc.res)
			if got != tc.expected {
				t.Errorf("flushInterval() = %v, want %v", got, tc.expected)
			}
		})
	}
}

