package reverseproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type customTimeoutError struct {
	msg string
}

func (e customTimeoutError) Error() string   { return e.msg }
func (e customTimeoutError) Timeout() bool   { return true }
func (e customTimeoutError) Temporary() bool { return true }

func TestDialError_UnwrapAndConstructor(t *testing.T) {
	if NewDialError(nil) != nil {
		t.Fatalf("NewDialError(nil) should return nil")
	}

	inner := errors.New("connection refused")
	dialErr := NewDialError(inner)

	if !errors.Is(dialErr, inner) {
		t.Errorf("errors.Is(dialErr, inner) should be true")
	}

	wrapped := fmt.Errorf("outer wrapper: %w", dialErr)
	var target DialError
	if !errors.As(wrapped, &target) {
		t.Fatalf("errors.As(wrapped, &target) should be true for DialError")
	}

	if target.Unwrap() != inner {
		t.Errorf("target.Unwrap() = %v, want %v", target.Unwrap(), inner)
	}
}

func TestTryAgain_ErrorWrapping(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	lb := LoadBalancing{
		Retries: 3,
	}

	// 1. Wrapped DialError on POST request should trigger tryAgain
	postReq, err := http.NewRequest("POST", "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	innerDialErr := NewDialError(errors.New("dial econnrefused"))
	wrappedDialErr := fmt.Errorf("handler wrapper: %w", innerDialErr)

	if !lb.tryAgain(ctx, time.Now(), 0, wrappedDialErr, postReq, zap.NewNop()) {
		t.Errorf("tryAgain() should return true for wrapped DialError on POST request")
	}

	// 2. Wrapped retryableResponseError
	rre := retryableResponseError{statusCode: 503}
	wrappedRRE := fmt.Errorf("wrapper: %w", rre)
	if !lb.tryAgain(ctx, time.Now(), 0, wrappedRRE, postReq, zap.NewNop()) {
		t.Errorf("tryAgain() should return true for wrapped retryableResponseError")
	}

	// 3. Wrapped HandlerError with errNoUpstream
	herr := caddyhttp.HandlerError{Err: fmt.Errorf("no upstream: %w", errNoUpstream), StatusCode: 503}
	if !lb.tryAgain(ctx, time.Now(), 0, herr, postReq, zap.NewNop()) {
		t.Errorf("tryAgain() should return true for HandlerError wrapping errNoUpstream")
	}
}

func TestStatusError_WrappedTimeout(t *testing.T) {
	timeoutErr := customTimeoutError{msg: "i/o timeout"}
	dialErr := NewDialError(timeoutErr)
	wrappedErr := fmt.Errorf("proxy error: %w", dialErr)

	err := statusError(wrappedErr)
	var hErr caddyhttp.HandlerError
	if !errors.As(err, &hErr) {
		t.Fatalf("statusError did not return HandlerError")
	}

	if hErr.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("statusError status code = %d, want %d (504)", hErr.StatusCode, http.StatusGatewayTimeout)
	}
}

func TestHTTPTransport_TLSHandshakeTimeout(t *testing.T) {
	// Start a TCP listener that accepts connections but does not perform TLS handshake
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// keep open without reading/writing so TLS handshake times out
			defer conn.Close()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ht := &HTTPTransport{
		TLS: &TLSConfig{
			HandshakeTimeout:   caddy.Duration(100 * time.Millisecond),
			InsecureSkipVerify: true,
		},
	}

	tr, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	req, err := http.NewRequest("GET", "https://"+ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, roundTripErr := tr.RoundTrip(req)
	if roundTripErr == nil {
		t.Fatalf("expected roundtrip error on TLS handshake timeout")
	}
	t.Logf("roundTripErr = %T: %v (unwrap: %T %v)", roundTripErr, roundTripErr, errors.Unwrap(roundTripErr), errors.Unwrap(roundTripErr))

	var dialErr DialError
	if !errors.As(roundTripErr, &dialErr) {
		t.Fatalf("TLS handshake timeout error was not wrapped in DialError: %v", roundTripErr)
	}

	lb := LoadBalancing{Retries: 3}
	postReq, _ := http.NewRequest("POST", "https://"+ln.Addr().String(), nil)
	if !lb.tryAgain(ctx, time.Now(), 0, roundTripErr, postReq, zap.NewNop()) {
		t.Errorf("tryAgain() returned false for TLS handshake timeout on POST request")
	}

	stErr := statusError(roundTripErr)
	var hErr caddyhttp.HandlerError
	if !errors.As(stErr, &hErr) {
		t.Fatalf("statusError did not return HandlerError")
	}
	if hErr.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("statusError code = %d, want %d (504)", hErr.StatusCode, http.StatusGatewayTimeout)
	}
}

func TestHTTPTransport_TLSHandshakeCertError(t *testing.T) {
	// Start a TLS server with self-signed certificate
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// Transport without skipping verification, so handshake fails certificate verification
	ht := &HTTPTransport{
		TLS: &TLSConfig{},
	}

	tr, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, roundTripErr := tr.RoundTrip(req)
	if roundTripErr == nil {
		t.Fatalf("expected roundtrip error on TLS cert error")
	}

	var dialErr DialError
	if !errors.As(roundTripErr, &dialErr) {
		t.Fatalf("TLS certificate failure was not wrapped in DialError: %v", roundTripErr)
	}
}
