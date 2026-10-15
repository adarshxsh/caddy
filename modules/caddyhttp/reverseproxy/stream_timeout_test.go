package reverseproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestHTTPTransport_StreamReadTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Sleep longer than ReadTimeout before sending response body
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("delayed response body"))
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	ht := &HTTPTransport{
		ReadTimeout: caddy.Duration(50 * time.Millisecond),
	}
	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	ht.Transport = rt

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}

	resp, err := ht.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error = %v", err)
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("expected read timeout error on response body, got nil")
	}

	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Errorf("expected net.Error with Timeout() == true, got %v", err)
	}
}

type slowReader struct {
	delay time.Duration
	data  []byte
	read  bool
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.read {
		return 0, io.EOF
	}
	time.Sleep(s.delay)
	s.read = true
	n := copy(p, s.data)
	return n, nil
}

func (s *slowReader) Close() error {
	return nil
}

func TestHTTPTransport_StreamWriteTimeout(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	ht := &HTTPTransport{
		WriteTimeout: caddy.Duration(50 * time.Millisecond),
	}
	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ht.Transport = rt

	body := &slowReader{
		delay: 200 * time.Millisecond,
		data:  []byte("slow request body"),
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL, body)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}

	resp, err := ht.RoundTrip(req)
	if err == nil {
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
	}

	if err == nil {
		t.Fatal("expected write timeout error when sending request body, got nil")
	}
}

func TestHTTPTransport_IdleConnectionRetention(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	ht := &HTTPTransport{
		ReadTimeout:  caddy.Duration(50 * time.Millisecond),
		WriteTimeout: caddy.Duration(50 * time.Millisecond),
		KeepAlive: &KeepAlive{
			IdleConnTimeout: caddy.Duration(5 * time.Second),
		},
	}
	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ht.Transport = rt

	// Request 1
	var reUsedFirst, reUsedSecond bool
	trace1 := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reUsedFirst = info.Reused
		},
	}
	req1, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace1), http.MethodGet, ts.URL, nil)
	resp1, err := ht.RoundTrip(req1)
	if err != nil {
		t.Fatalf("req1 RoundTrip error: %v", err)
	}
	_, _ = io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if reUsedFirst {
		t.Error("expected first connection not to be reused")
	}

	// Sleep longer than ReadTimeout/WriteTimeout (50ms) but less than IdleConnTimeout (5s)
	time.Sleep(150 * time.Millisecond)

	// Request 2
	trace2 := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reUsedSecond = info.Reused
		},
	}
	req2, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace2), http.MethodGet, ts.URL, nil)
	resp2, err := ht.RoundTrip(req2)
	if err != nil {
		t.Fatalf("req2 RoundTrip error: %v", err)
	}
	_, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if !reUsedSecond {
		t.Errorf("expected second request to reuse pooled connection after idle time > ReadTimeout, but reUsedSecond = false")
	}
}

func TestHTTPTransport_HTTP2_StreamMultiplexing(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("h2 ok"))
	})

	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	ht := &HTTPTransport{
		Versions:     []string{"2"},
		ReadTimeout:  caddy.Duration(50 * time.Millisecond),
		WriteTimeout: caddy.Duration(50 * time.Millisecond),
		TLS: &TLSConfig{
			InsecureSkipVerify: true,
		},
	}

	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ht.Transport = rt

	// Stream 1
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp1, err := ht.RoundTrip(req1)
	if err != nil {
		t.Fatalf("H2 Stream 1 RoundTrip error: %v", err)
	}
	b1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(b1) != "h2 ok" {
		t.Errorf("unexpected body 1: %s", string(b1))
	}

	// Idle period longer than ReadTimeout
	time.Sleep(150 * time.Millisecond)

	// Stream 2 on same multiplexed connection
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp2, err := ht.RoundTrip(req2)
	if err != nil {
		t.Fatalf("H2 Stream 2 RoundTrip error across idle period: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(b2) != "h2 ok" {
		t.Errorf("unexpected body 2: %s", string(b2))
	}
}
