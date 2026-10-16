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
		name           string
		flushInterval  caddy.Duration
		reqProtoMajor  int
		resProtoMajor  int
		contentType    string
		acceptEncoding string
		contentLength  int64
		want           time.Duration
	}{
		{
			name:          "chunked response with positive flush interval",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentLength: -1,
			want:          250 * time.Millisecond,
		},
		{
			name:          "chunked response with negative flush interval",
			flushInterval: caddy.Duration(-1),
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentLength: -1,
			want:          -1,
		},
		{
			name:          "chunked response with default flush interval",
			flushInterval: 0,
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentLength: -1,
			want:          0,
		},
		{
			name:          "SSE response flushes immediately despite positive flush interval",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentType:   "text/event-stream",
			contentLength: -1,
			want:          -1,
		},
		{
			name:          "SSE response with parameters flushes immediately",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentType:   "text/event-stream; charset=utf-8",
			contentLength: -1,
			want:          -1,
		},
		{
			name:           "H2 bidirectional stream flushes immediately",
			flushInterval:  caddy.Duration(250 * time.Millisecond),
			reqProtoMajor:  2,
			resProtoMajor:  2,
			acceptEncoding: "identity",
			contentLength:  -1,
			want:           -1,
		},
		{
			name:          "fixed content length response returns configured flush interval",
			flushInterval: caddy.Duration(250 * time.Millisecond),
			reqProtoMajor: 1,
			resProtoMajor: 1,
			contentLength: 100,
			want:          250 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{
				FlushInterval: tt.flushInterval,
			}
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.ProtoMajor = tt.reqProtoMajor
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			res := &http.Response{
				ProtoMajor:    tt.resProtoMajor,
				Header:        make(http.Header),
				ContentLength: tt.contentLength,
			}
			if tt.contentType != "" {
				res.Header.Set("Content-Type", tt.contentType)
			}

			got := h.flushInterval(req, res)
			if got != tt.want {
				t.Errorf("flushInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandlerCopyResponseWithFlushInterval(t *testing.T) {
	h := Handler{
		FlushInterval: caddy.Duration(50 * time.Millisecond),
	}

	pr, pw := io.Pipe()
	recorder := httptest.NewRecorder()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1,
		Body:          pr,
		Header:        make(http.Header),
	}

	fi := h.flushInterval(req, res)
	if fi != 50*time.Millisecond {
		t.Fatalf("expected flushInterval 50ms for chunked response, got %v", fi)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.copyResponse(recorder, res.Body, fi, caddy.Log())
	}()

	_, err := pw.Write([]byte("chunk 1"))
	if err != nil {
		t.Fatalf("failed to write chunk 1: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	_, err = pw.Write([]byte("chunk 2"))
	if err != nil {
		t.Fatalf("failed to write chunk 2: %v", err)
	}

	pw.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("copyResponse returned error: %v", err)
	}

	if got := recorder.Body.String(); got != "chunk 1chunk 2" {
		t.Errorf("got response body %q, want %q", got, "chunk 1chunk 2")
	}
}
