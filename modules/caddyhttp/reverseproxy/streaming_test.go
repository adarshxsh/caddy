package reverseproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

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

func TestExtractQUICResetCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode quic.StreamErrorCode
		wantOK   bool
	}{
		{
			name:     "nil error",
			err:      nil,
			wantCode: 0,
			wantOK:   false,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			wantCode: 0,
			wantOK:   false,
		},
		{
			name:     "http3.Error",
			err:      &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled},
			wantCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
			wantOK:   true,
		},
		{
			name:     "wrapped http3.Error",
			err:      fmt.Errorf("reading: %w", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}),
			wantCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError",
			err:      &quic.ApplicationError{ErrorCode: 0x42},
			wantCode: 0x42,
			wantOK:   true,
		},
		{
			name:     "wrapped quic.ApplicationError",
			err:      fmt.Errorf("writing: %w", &quic.ApplicationError{ErrorCode: 0x42}),
			wantCode: 0x42,
			wantOK:   true,
		},
		{
			name:     "quic.StreamError",
			err:      &quic.StreamError{ErrorCode: 0x21},
			wantCode: 0x21,
			wantOK:   true,
		},
		{
			name:     "wrapped quic.StreamError",
			err:      fmt.Errorf("reading: %w", &quic.StreamError{ErrorCode: 0x21}),
			wantCode: 0x21,
			wantOK:   true,
		},
		{
			name:     "http2.StreamError ErrCodeCancel",
			err:      http2.StreamError{Code: http2.ErrCodeCancel},
			wantCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
			wantOK:   true,
		},
		{
			name:     "wrapped http2.StreamError",
			err:      fmt.Errorf("reading: %w", http2.StreamError{Code: http2.ErrCodeCancel}),
			wantCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCode, gotOK := extractQUICResetCode(tt.err)
			if gotOK != tt.wantOK {
				t.Errorf("extractQUICResetCode() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if gotCode != tt.wantCode {
				t.Errorf("extractQUICResetCode() gotCode = %v, want %v", gotCode, tt.wantCode)
			}
		})
	}
}

func TestGetHTTPStreamer(t *testing.T) {
	rec := httptest.NewRecorder()
	ms := mockStreamer{ResponseWriter: rec}

	if streamer := getHTTPStreamer(ms); streamer != ms {
		t.Errorf("getHTTPStreamer(ms) = %v, want %v", streamer, ms)
	}

	wrapped := wrappedResponseWriter{ResponseWriter: ms}
	if streamer := getHTTPStreamer(wrapped); streamer != ms {
		t.Errorf("getHTTPStreamer(wrapped) = %v, want %v", streamer, ms)
	}

	sliceWrapped := sliceWrappedResponseWriter{ResponseWriter: wrapped}
	if streamer := getHTTPStreamer(sliceWrapped); streamer != ms {
		t.Errorf("getHTTPStreamer(sliceWrapped) = %v, want %v", streamer, ms)
	}

	if streamer := getHTTPStreamer(rec); streamer != nil {
		t.Errorf("getHTTPStreamer(rec) = %v, want nil", streamer)
	}
}

func TestCancelDownstreamHTTP3Stream(t *testing.T) {
	rec := httptest.NewRecorder()
	ms := mockStreamer{ResponseWriter: rec, str: nil}
	wrapped := wrappedResponseWriter{ResponseWriter: ms}

	h3Err := &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}
	code, hasCode := cancelDownstreamHTTP3Stream(wrapped, fmt.Errorf("reading: %w", h3Err))

	if !hasCode {
		t.Fatalf("expected hasCode = true")
	}
	if code != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
		t.Fatalf("got code %v, want %v", code, http3.ErrCodeRequestCanceled)
	}

	// Non-QUIC error
	code, hasCode = cancelDownstreamHTTP3Stream(wrapped, errors.New("generic error"))
	if hasCode {
		t.Fatalf("expected hasCode = false for generic error")
	}
}

type mockStreamer struct {
	http.ResponseWriter
	str *http3.Stream
}

func (m mockStreamer) HTTPStream() *http3.Stream {
	return m.str
}

type wrappedResponseWriter struct {
	http.ResponseWriter
}

func (w wrappedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type sliceWrappedResponseWriter struct {
	http.ResponseWriter
}

func (w sliceWrappedResponseWriter) Unwrap() []http.ResponseWriter {
	return []http.ResponseWriter{w.ResponseWriter}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
