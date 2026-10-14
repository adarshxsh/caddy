package fastcgi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create dead upstream listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestFastCGI_DialErrorWrapping(t *testing.T) {
	deadAddr := deadUpstreamAddr(t)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	fcgi := Transport{
		DialTimeout: caddy.Duration(100 * time.Millisecond),
	}
	if err := fcgi.Provision(ctx); err != nil {
		t.Fatalf("failed to provision fastcgi transport: %v", err)
	}

	req, err := http.NewRequest("POST", "http://"+deadAddr+"/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})

	_, fcgiErr := fcgi.RoundTrip(req)
	if fcgiErr == nil {
		t.Fatalf("expected error from FastCGI RoundTrip to dead address")
	}

	var dialErr reverseproxy.DialError
	if !errors.As(fcgiErr, &dialErr) {
		t.Fatalf("FastCGI RoundTrip error is not wrapped in reverseproxy.DialError: %v", fcgiErr)
	}

	// Verify unwrapping returns the underlying dial error
	if dialErr.Unwrap() == nil {
		t.Errorf("dialErr.Unwrap() returned nil")
	}
}
