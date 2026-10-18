package reverseproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestExtractQUICErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode quic.StreamErrorCode
		wantOK   bool
	}{
		{
			name:     "quic.StreamError direct",
			err:      &quic.StreamError{ErrorCode: 0x101},
			wantCode: 0x101,
			wantOK:   true,
		},
		{
			name:     "quic.StreamError wrapped in reading",
			err:      fmt.Errorf("reading: %w", &quic.StreamError{ErrorCode: 0x102}),
			wantCode: 0x102,
			wantOK:   true,
		},
		{
			name:     "quic.StreamError wrapped in writing",
			err:      fmt.Errorf("writing: %w", &quic.StreamError{ErrorCode: 0x103}),
			wantCode: 0x103,
			wantOK:   true,
		},
		{
			name:     "http3.Error direct",
			err:      &http3.Error{ErrorCode: 0x10c},
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "http3.Error wrapped in reading",
			err:      fmt.Errorf("reading: %w", &http3.Error{ErrorCode: 0x10c}),
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "http3.Error wrapped in writing",
			err:      fmt.Errorf("writing: %w", &http3.Error{ErrorCode: 0x10c}),
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError direct",
			err:      &quic.ApplicationError{ErrorCode: 0x200},
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError wrapped in reading",
			err:      fmt.Errorf("reading: %w", &quic.ApplicationError{ErrorCode: 0x200}),
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError wrapped in writing",
			err:      fmt.Errorf("writing: %w", &quic.ApplicationError{ErrorCode: 0x200}),
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "standard io error",
			err:      io.ErrUnexpectedEOF,
			wantCode: 0,
			wantOK:   false,
		},
		{
			name:     "standard wrapped io error",
			err:      fmt.Errorf("reading: %w", io.ErrClosedPipe),
			wantCode: 0,
			wantOK:   false,
		},
		{
			name:     "generic error",
			err:      errors.New("connection reset by peer"),
			wantCode: 0,
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCode, gotOK := extractQUICErrorCode(tt.err)
			if gotOK != tt.wantOK {
				t.Errorf("extractQUICErrorCode() ok = %v, wantOK %v", gotOK, tt.wantOK)
			}
			if gotCode != tt.wantCode {
				t.Errorf("extractQUICErrorCode() code = %v, wantCode %v", gotCode, tt.wantCode)
			}
		})
	}
}

type testHTTPStreamer struct {
	http.ResponseWriter
	stream *http3.Stream
}

func (s testHTTPStreamer) HTTPStream() *http3.Stream {
	return s.stream
}

type multiUnwrapper struct {
	http.ResponseWriter
	children []http.ResponseWriter
}

func (m multiUnwrapper) Unwrap() []http.ResponseWriter {
	return m.children
}

func TestFindHTTPStreamer(t *testing.T) {
	streamer := testHTTPStreamer{ResponseWriter: httptest.NewRecorder()}

	t.Run("direct streamer", func(t *testing.T) {
		got := findHTTPStreamer(streamer)
		if got == nil {
			t.Fatal("expected streamer, got nil")
		}
	})

	t.Run("wrapped in ResponseWriterWrapper", func(t *testing.T) {
		wrapped := &caddyhttp.ResponseWriterWrapper{ResponseWriter: streamer}
		got := findHTTPStreamer(wrapped)
		if got == nil {
			t.Fatal("expected streamer through single wrapper, got nil")
		}
	})

	t.Run("wrapped in double ResponseWriterWrapper", func(t *testing.T) {
		wrapped1 := &caddyhttp.ResponseWriterWrapper{ResponseWriter: streamer}
		wrapped2 := &caddyhttp.ResponseWriterWrapper{ResponseWriter: wrapped1}
		got := findHTTPStreamer(wrapped2)
		if got == nil {
			t.Fatal("expected streamer through double wrapper, got nil")
		}
	})

	t.Run("multi unwrapper", func(t *testing.T) {
		multi := multiUnwrapper{
			ResponseWriter: httptest.NewRecorder(),
			children: []http.ResponseWriter{
				httptest.NewRecorder(),
				&caddyhttp.ResponseWriterWrapper{ResponseWriter: streamer},
			},
		}
		got := findHTTPStreamer(multi)
		if got == nil {
			t.Fatal("expected streamer through multi unwrapper, got nil")
		}
	})

	t.Run("non streamer recorder", func(t *testing.T) {
		rec := httptest.NewRecorder()
		got := findHTTPStreamer(rec)
		if got != nil {
			t.Fatalf("expected nil for standard recorder, got %v", got)
		}
	})
}
