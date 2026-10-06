package reverseproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type mockTimeoutError struct{}

func (m mockTimeoutError) Error() string   { return "connection timed out" }
func (m mockTimeoutError) Timeout() bool   { return true }
func (m mockTimeoutError) Temporary() bool { return true }

func TestDialErrorUnwrap(t *testing.T) {
	innerErr := errors.New("underlying dial failure")
	dialErr := DialError{Err: innerErr}

	if !errors.Is(dialErr, innerErr) {
		t.Errorf("expected errors.Is(dialErr, innerErr) to be true")
	}

	var target DialError
	if errors.As(dialErr, &target) {
		if target.Unwrap() != innerErr {
			t.Errorf("expected Unwrap to return innerErr, got %v", target.Unwrap())
		}
	} else {
		t.Errorf("expected DialError to be targetable by errors.As")
	}

	// Test double wrapped error
	wrappedDialErr := fmt.Errorf("outer wrapper: %w", dialErr)
	var foundDialErr DialError
	if !errors.As(wrappedDialErr, &foundDialErr) {
		t.Errorf("expected errors.As to find DialError inside wrapped error")
	}

	var foundNetErr net.Error
	mockNetErr := mockTimeoutError{}
	dialNetErr := fmt.Errorf("outer wrapper: %w", DialError{Err: mockNetErr})
	if !errors.As(dialNetErr, &foundNetErr) {
		t.Errorf("expected errors.As to find net.Error inside DialError wrapper")
	} else if !foundNetErr.Timeout() {
		t.Errorf("expected netErr.Timeout() to be true")
	}
}

func TestStatusErrorGatewayTimeout(t *testing.T) {
	mockNetErr := mockTimeoutError{}

	// 1. Direct timeout error
	err1 := statusError(mockNetErr)
	if handlerErr, ok := err1.(caddyhttp.HandlerError); ok {
		if handlerErr.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("expected status 504 Gateway Timeout, got %d", handlerErr.StatusCode)
		}
	} else {
		t.Errorf("expected statusError to return HandlerError")
	}

	// 2. Timeout error wrapped in DialError
	dialErr := DialError{Err: mockNetErr}
	err2 := statusError(dialErr)
	if handlerErr, ok := err2.(caddyhttp.HandlerError); ok {
		if handlerErr.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("expected status 504 Gateway Timeout for DialError{mockNetErr}, got %d", handlerErr.StatusCode)
		}
	} else {
		t.Errorf("expected statusError to return HandlerError")
	}

	// 3. Timeout error inside wrapped DialError
	fmtErr := fmt.Errorf("proxy failed: %w", DialError{Err: mockNetErr})
	err3 := statusError(fmtErr)
	if handlerErr, ok := err3.(caddyhttp.HandlerError); ok {
		if handlerErr.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("expected status 504 Gateway Timeout for wrapped DialError, got %d", handlerErr.StatusCode)
		}
	} else {
		t.Errorf("expected statusError to return HandlerError")
	}

	// 4. Non-timeout DialError should yield 502 Bad Gateway
	standardDialErr := DialError{Err: errors.New("connection refused")}
	err4 := statusError(standardDialErr)
	if handlerErr, ok := err4.(caddyhttp.HandlerError); ok {
		if handlerErr.StatusCode != http.StatusBadGateway {
			t.Errorf("expected status 502 Bad Gateway for standard DialError, got %d", handlerErr.StatusCode)
		}
	} else {
		t.Errorf("expected statusError to return HandlerError")
	}
}

func TestTryAgainWithWrappedDialError(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/api", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	lb := &LoadBalancing{
		Retries: 2,
	}

	// Wrapped dial error should be retryable for POST request
	wrappedErr := fmt.Errorf("outer transport error: %w", DialError{Err: errors.New("connection refused")})
	retry := lb.tryAgain(caddy.Context{}, time.Now(), 0, wrappedErr, req, zap.NewNop())
	if !retry {
		t.Errorf("expected tryAgain to return true for POST request with wrapped DialError")
	}

	// Non-dial error on POST request should NOT be retryable
	nonDialErr := fmt.Errorf("http stream error: %w", errors.New("connection reset by peer"))
	retryNonDial := lb.tryAgain(caddy.Context{}, time.Now(), 0, nonDialErr, req, zap.NewNop())
	if retryNonDial {
		t.Errorf("expected tryAgain to return false for POST request with non-dial error")
	}
}
