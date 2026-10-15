package reverseproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type mockDatagramStream struct {
	canceledWriteCode quic.StreamErrorCode
	canceledReadCode  quic.StreamErrorCode
	canceledWrite     bool
	canceledRead      bool
}

func (m *mockDatagramStream) Read(p []byte) (int, error)  { return 0, io.EOF }
func (m *mockDatagramStream) Write(p []byte) (int, error) { return len(p), nil }
func (m *mockDatagramStream) Close() error                { return nil }
func (m *mockDatagramStream) CancelRead(code quic.StreamErrorCode) {
	m.canceledRead = true
	m.canceledReadCode = code
}
func (m *mockDatagramStream) CancelWrite(code quic.StreamErrorCode) {
	m.canceledWrite = true
	m.canceledWriteCode = code
}
func (m *mockDatagramStream) StreamID() quic.StreamID            { return 1 }
func (m *mockDatagramStream) Context() context.Context           { return context.Background() }
func (m *mockDatagramStream) SetDeadline(t time.Time) error      { return nil }
func (m *mockDatagramStream) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockDatagramStream) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockDatagramStream) SendDatagram(b []byte) error        { return nil }
func (m *mockDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return nil, nil
}
func (m *mockDatagramStream) QUICStream() *quic.Stream { return nil }

type mockHTTPStreamer struct {
	stream *http3.Stream
}

func (m *mockHTTPStreamer) HTTPStream() *http3.Stream {
	return m.stream
}

func newMockHTTP3Stream(mockDS *mockDatagramStream) *http3.Stream {
	stream := &http3.Stream{}
	val := reflect.ValueOf(stream).Elem().FieldByName("datagramStream")
	reflect.NewAt(val.Type(), unsafe.Pointer(val.UnsafeAddr())).Elem().Set(reflect.ValueOf(mockDS))
	return stream
}

type testWrapperResponseWriter struct {
	rw http.ResponseWriter
}

func (w *testWrapperResponseWriter) Header() http.Header         { return w.rw.Header() }
func (w *testWrapperResponseWriter) Write(b []byte) (int, error) { return w.rw.Write(b) }
func (w *testWrapperResponseWriter) WriteHeader(statusCode int)  { w.rw.WriteHeader(statusCode) }
func (w *testWrapperResponseWriter) Unwrap() http.ResponseWriter { return w.rw }

type streamerResponseWriter struct {
	http.ResponseWriter
	streamer http3.HTTPStreamer
}

func (s *streamerResponseWriter) HTTPStream() *http3.Stream {
	return s.streamer.HTTPStream()
}

func TestExtractQUICErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode quic.StreamErrorCode
		wantOK   bool
	}{
		{
			name:     "quic.StreamError",
			err:      &quic.StreamError{ErrorCode: 0x10c},
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "http3.Error",
			err:      &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled},
			wantCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError",
			err:      &quic.ApplicationError{ErrorCode: 0x100},
			wantCode: 0x100,
			wantOK:   true,
		},
		{
			name:     "wrapped quic.StreamError",
			err:      fmt.Errorf("reading: %w", &quic.StreamError{ErrorCode: 0x200}),
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "non-quic error",
			err:      io.ErrUnexpectedEOF,
			wantCode: 0,
			wantOK:   false,
		},
		{
			name:     "nil error",
			err:      nil,
			wantCode: 0,
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCode, gotOK := extractQUICErrorCode(tt.err)
			if gotOK != tt.wantOK {
				t.Errorf("extractQUICErrorCode() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if gotCode != tt.wantCode {
				t.Errorf("extractQUICErrorCode() gotCode = %v, want %v", gotCode, tt.wantCode)
			}
		})
	}
}

func TestUnwrapHTTPStreamer(t *testing.T) {
	mockDS := &mockDatagramStream{}
	stream := newMockHTTP3Stream(mockDS)
	streamer := &mockHTTPStreamer{stream: stream}

	sw := &streamerResponseWriter{ResponseWriter: httptest.NewRecorder(), streamer: streamer}
	w1 := &testWrapperResponseWriter{rw: sw}
	w2 := &testWrapperResponseWriter{rw: w1}

	if got := unwrapHTTPStreamer(w2); got != sw {
		t.Errorf("unwrapHTTPStreamer(w2) = %v, want %v", got, sw)
	}

	if got := unwrapHTTPStreamer(sw); got != sw {
		t.Errorf("unwrapHTTPStreamer(sw) = %v, want %v", got, sw)
	}

	nonStreamer := httptest.NewRecorder()
	if got := unwrapHTTPStreamer(nonStreamer); got != nil {
		t.Errorf("unwrapHTTPStreamer(nonStreamer) = %v, want nil", got)
	}
}

func TestReverseProxyQUICStreamReset(t *testing.T) {
	mockDS := &mockDatagramStream{}
	stream := newMockHTTP3Stream(mockDS)
	streamer := &mockHTTPStreamer{stream: stream}

	rec := httptest.NewRecorder()
	sw := &streamerResponseWriter{ResponseWriter: rec, streamer: streamer}
	wrapper := &caddyhttp.ResponseWriterWrapper{ResponseWriter: sw}

	h := Handler{
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com/stream", nil)
	repl := caddy.NewReplacer()
	const expectedErrCode = quic.StreamErrorCode(0x10c)
	failingBody := &errorReader{err: &quic.StreamError{ErrorCode: expectedErrCode}}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       failingBody,
		Header:     make(http.Header),
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on reverse proxy stream failure, got nil")
		}
		if r != http.ErrAbortHandler {
			t.Fatalf("expected panic(http.ErrAbortHandler), got %v", r)
		}

		if !mockDS.canceledWrite {
			t.Errorf("expected CancelWrite to be called")
		}
		if mockDS.canceledWriteCode != expectedErrCode {
			t.Errorf("CancelWrite code = %v, want %v", mockDS.canceledWriteCode, expectedErrCode)
		}
		if !mockDS.canceledRead {
			t.Errorf("expected CancelRead to be called")
		}
		if mockDS.canceledReadCode != expectedErrCode {
			t.Errorf("CancelRead code = %v, want %v", mockDS.canceledReadCode, expectedErrCode)
		}
	}()

	_ = h.finalizeResponse(wrapper, req, res, repl, time.Now(), zap.NewNop())
}

func TestReverseProxyNonQUICErrorFallback(t *testing.T) {
	mockDS := &mockDatagramStream{}
	stream := newMockHTTP3Stream(mockDS)
	streamer := &mockHTTPStreamer{stream: stream}

	rec := httptest.NewRecorder()
	sw := &streamerResponseWriter{ResponseWriter: rec, streamer: streamer}
	wrapper := &caddyhttp.ResponseWriterWrapper{ResponseWriter: sw}

	h := Handler{
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com/stream", nil)
	repl := caddy.NewReplacer()
	failingBody := &errorReader{err: io.ErrUnexpectedEOF}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       failingBody,
		Header:     make(http.Header),
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on reverse proxy stream failure, got nil")
		}
		if r != http.ErrAbortHandler {
			t.Fatalf("expected panic(http.ErrAbortHandler), got %v", r)
		}

		if mockDS.canceledWrite {
			t.Errorf("CancelWrite should NOT be called for non-QUIC error")
		}
		if mockDS.canceledRead {
			t.Errorf("CancelRead should NOT be called for non-QUIC error")
		}
	}()

	_ = h.finalizeResponse(wrapper, req, res, repl, time.Now(), zap.NewNop())
}

type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, e.err
}

func (e *errorReader) Close() error {
	return nil
}
