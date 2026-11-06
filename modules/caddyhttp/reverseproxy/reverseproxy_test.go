package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestReverseProxyNonCanonicalHopByHopHeaders(t *testing.T) {
	// Backend server that verifies no hop-by-hop headers are received
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that no non-canonical or hop-by-hop headers reached the backend
		hopByHopKeys := []string{
			"connection", "Connection",
			"custom-hop", "Custom-Hop",
			"alt-svc", "Alt-Svc",
			"proxy-authorization", "Proxy-Authorization",
			"keep-alive", "Keep-Alive",
			"transfer-encoding", "Transfer-Encoding",
			"upgrade", "Upgrade",
		}
		for _, k := range hopByHopKeys {
			if _, exists := r.Header[k]; exists {
				t.Errorf("backend received unexpected hop-by-hop header key %q: %v", k, r.Header[k])
			}
		}

		// Send response with non-canonical hop-by-hop headers
		w.Header()["connection"] = []string{"close"}
		w.Header()["alt-svc"] = []string{"h3=\":443\""}
		w.Header()["keep-alive"] = []string{"timeout=10"}
		w.Header()["proxy-authorization"] = []string{"Basic secret"}
		w.Header()["x-custom-response"] = []string{"ok"}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}

	transport := &HTTPTransport{}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := transport.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision transport: %v", err)
	}

	handler := &Handler{
		logger:    zap.NewNop(),
		Transport: transport,
		Upstreams: UpstreamPool{
			{Dial: backendURL.Host, Host: new(Host)},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	// Create client request with non-canonical hop-by-hop headers
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header["connection"] = []string{"close, custom-hop"}
	req.Header["custom-hop"] = []string{"client-secret"}
	req.Header["alt-svc"] = []string{"h3=\":443\""}
	req.Header["proxy-authorization"] = []string{"Basic 12345"}
	req.Header["keep-alive"] = []string{"timeout=5"}
	req.Header["x-custom-request"] = []string{"hello"}

	// Set required replacer and vars in context
	repl := caddy.NewReplacer()
	vars := map[string]any{
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctxWithRepl := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctxWithRepl = context.WithValue(ctxWithRepl, caddyhttp.VarsCtxKey, vars)
	ctxWithRepl = context.WithValue(ctxWithRepl, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
	req = req.WithContext(ctxWithRepl)

	rr := httptest.NewRecorder()
	noopHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err = handler.ServeHTTP(rr, req, noopHandler)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	res := rr.Result()
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", string(body), "backend response")
	}

	// Verify downstream client received no non-canonical hop-by-hop response headers
	resHopByHopKeys := []string{
		"connection", "Connection",
		"alt-svc", "Alt-Svc",
		"keep-alive", "Keep-Alive",
		"proxy-authorization", "Proxy-Authorization",
	}
	for _, k := range resHopByHopKeys {
		if _, exists := res.Header[k]; exists {
			t.Errorf("client received unexpected hop-by-hop response header key %q: %v", k, res.Header[k])
		}
	}

	if got := res.Header.Get("X-Custom-Response"); got != "ok" {
		t.Errorf("X-Custom-Response = %q, want %q", got, "ok")
	}
}
