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
			name:          "Positive FlushInterval with ContentLength == -1",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header:        make(http.Header),
				ContentLength: -1,
			},
			expected: 100 * time.Millisecond,
		},
		{
			name:          "Explicit negative FlushInterval with ContentLength == -1",
			flushInterval: caddy.Duration(-1),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header:        make(http.Header),
				ContentLength: -1,
			},
			expected: -1,
		},
		{
			name:          "Unconfigured FlushInterval (0) with ContentLength == -1",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header:        make(http.Header),
				ContentLength: -1,
			},
			expected: -1,
		},
		{
			name:          "Server-Sent Events overrides positive FlushInterval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"text/event-stream"},
				},
				ContentLength: -1,
			},
			expected: -1,
		},
		{
			name:          "Bidirectional stream overrides positive FlushInterval",
			flushInterval: caddy.Duration(100 * time.Millisecond),
			req: &http.Request{
				ProtoMajor: 2,
				Header:     http.Header{"Accept-Encoding": []string{"identity"}},
			},
			res: &http.Response{
				ProtoMajor:    2,
				Header:        make(http.Header),
				ContentLength: -1,
			},
			expected: -1,
		},
		{
			name:          "Unconfigured FlushInterval (0) with known ContentLength",
			flushInterval: 0,
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header:        make(http.Header),
				ContentLength: 100,
			},
			expected: 0,
		},
		{
			name:          "Positive FlushInterval with known ContentLength",
			flushInterval: caddy.Duration(200 * time.Millisecond),
			req:           httptest.NewRequest("GET", "/", nil),
			res: &http.Response{
				Header:        make(http.Header),
				ContentLength: 100,
			},
			expected: 200 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{
				FlushInterval: tt.flushInterval,
			}
			got := h.flushInterval(tt.req, tt.res)
			if got != tt.expected {
				t.Errorf("flushInterval() = %v, want %v", got, tt.expected)
			}
		})
	}
}

