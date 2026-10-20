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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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

func TestExtractQUICResetCode(t *testing.T) {
	strErr := &quic.StreamError{
		StreamID:  42,
		ErrorCode: quic.StreamErrorCode(0x10c),
		Remote:    true,
	}
	appErr := &quic.ApplicationError{
		ErrorCode: quic.ApplicationErrorCode(0x200),
		Remote:    true,
	}
	h3Err := &http3.Error{
		ErrorCode: http3.ErrCodeInternalError,
		Remote:    false,
	}

	tests := []struct {
		name     string
		err      error
		wantCode quic.StreamErrorCode
		wantOK   bool
	}{
		{
			name:     "quic.StreamError direct",
			err:      strErr,
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "quic.StreamError wrapped",
			err:      fmt.Errorf("reading: %w", strErr),
			wantCode: 0x10c,
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError direct",
			err:      appErr,
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "quic.ApplicationError wrapped",
			err:      fmt.Errorf("reading: %w", appErr),
			wantCode: 0x200,
			wantOK:   true,
		},
		{
			name:     "http3.Error direct",
			err:      h3Err,
			wantCode: quic.StreamErrorCode(http3.ErrCodeInternalError),
			wantOK:   true,
		},
		{
			name:     "http3.Error wrapped",
			err:      fmt.Errorf("reading: %w", h3Err),
			wantCode: quic.StreamErrorCode(http3.ErrCodeInternalError),
			wantOK:   true,
		},
		{
			name:     "generic error",
			err:      errors.New("generic network error"),
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
			gotCode, gotOK := extractQUICResetCode(tt.err)
			if gotOK != tt.wantOK {
				t.Errorf("extractQUICResetCode() ok = %v, wantOK %v", gotOK, tt.wantOK)
			}
			if gotCode != tt.wantCode {
				t.Errorf("extractQUICResetCode() code = %#x, wantCode %#x", gotCode, tt.wantCode)
			}
		})
	}
}

type cancelWriteRecorder struct {
	http.ResponseWriter
	canceledCode quic.StreamErrorCode
	cancelCalled bool
}

func (c *cancelWriteRecorder) CancelWrite(code quic.StreamErrorCode) {
	c.canceledCode = code
	c.cancelCalled = true
}

func TestTryCancelWrite(t *testing.T) {
	t.Run("direct CancelWrite recorder", func(t *testing.T) {
		rec := &cancelWriteRecorder{ResponseWriter: httptest.NewRecorder()}
		ok := tryCancelWrite(rec, 0x10c)
		if !ok {
			t.Fatalf("expected tryCancelWrite to return true")
		}
		if !rec.cancelCalled {
			t.Errorf("expected CancelWrite to be called")
		}
		if rec.canceledCode != 0x10c {
			t.Errorf("got code %#x, want 0x10c", rec.canceledCode)
		}
	})

	t.Run("wrapped inside ResponseWriterWrapper", func(t *testing.T) {
		rec := &cancelWriteRecorder{ResponseWriter: httptest.NewRecorder()}
		wrapped := &caddyhttp.ResponseWriterWrapper{ResponseWriter: rec}
		wrapped2 := &caddyhttp.ResponseWriterWrapper{ResponseWriter: wrapped}

		ok := tryCancelWrite(wrapped2, 0x101)
		if !ok {
			t.Fatalf("expected tryCancelWrite through wrappers to return true")
		}
		if !rec.cancelCalled {
			t.Errorf("expected CancelWrite to be called")
		}
		if rec.canceledCode != 0x101 {
			t.Errorf("got code %#x, want 0x101", rec.canceledCode)
		}
	})

	t.Run("standard ResponseWriter without cancellation", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ok := tryCancelWrite(rec, 0x10c)
		if ok {
			t.Fatalf("expected tryCancelWrite to return false for standard recorder")
		}
	})
}

type errorReader struct {
	data []byte
	err  error
}

func (e *errorReader) Read(p []byte) (int, error) {
	if len(e.data) > 0 {
		n := copy(p, e.data)
		e.data = e.data[n:]
		return n, nil
	}
	return 0, e.err
}

func TestCopyResponse_QUICStreamResetPropagation(t *testing.T) {
	strErr := &quic.StreamError{
		StreamID:  1,
		ErrorCode: quic.StreamErrorCode(0x10c),
		Remote:    true,
	}

	src := &errorReader{
		data: []byte("partial content..."),
		err:  strErr,
	}

	rec := &cancelWriteRecorder{ResponseWriter: httptest.NewRecorder()}
	wrapped := &caddyhttp.ResponseWriterWrapper{ResponseWriter: rec}

	h := Handler{}
	err := h.copyResponse(wrapped, src, 0, caddy.Log())
	if err == nil {
		t.Fatalf("expected error from copyResponse, got nil")
	}

	code, ok := extractQUICResetCode(err)
	if !ok {
		t.Fatalf("expected extractQUICResetCode to find QUIC reset code")
	}
	if code != 0x10c {
		t.Errorf("got code %#x, want 0x10c", code)
	}

	cancelled := tryCancelWrite(wrapped, code)
	if !cancelled {
		t.Fatalf("expected tryCancelWrite to succeed")
	}
	if !rec.cancelCalled {
		t.Errorf("expected CancelWrite to be called")
	}
	if rec.canceledCode != 0x10c {
		t.Errorf("got canceled code %#x, want 0x10c", rec.canceledCode)
	}
}
