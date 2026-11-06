package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestReverseProxyPreannouncedTrailers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
	}))
	defer backend.Close()

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: &HTTPTransport{Transport: &http.Transport{}},
		Upstreams: UpstreamPool{
			&Upstream{
				Dial: backend.Listener.Addr().String(),
				Host: new(Host),
			},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "http"
		vars := map[string]any{
			caddyhttp.TrustedProxyVarKey: false,
			caddyhttp.ClientIPVarKey:     "127.0.0.1",
		}
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.ServerCtxKey, &caddyhttp.Server{}))
		if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		})); err != nil {
			t.Errorf("ServeHTTP returned error: %v", err)
		}
	}))
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if string(body) != "hello world" {
		t.Errorf("Expected body 'hello world', got %q", string(body))
	}

	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Expected Grpc-Status trailer '0', got %q", got)
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "OK" {
		t.Errorf("Expected Grpc-Message trailer 'OK', got %q", got)
	}
}
