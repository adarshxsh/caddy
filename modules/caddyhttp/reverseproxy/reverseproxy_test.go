package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestCanonicalizeHeaders(t *testing.T) {
	h := http.Header{
		"connection":        []string{"close"},
		"transfer-encoding": []string{"chunked"},
		"X-Custom-Header":   []string{"val1"},
		"x-custom-header":   []string{"val2"},
	}

	canonicalizeHeaders(h)

	if _, ok := h["connection"]; ok {
		t.Errorf("expected 'connection' to be deleted")
	}
	if _, ok := h["transfer-encoding"]; ok {
		t.Errorf("expected 'transfer-encoding' to be deleted")
	}
	if _, ok := h["x-custom-header"]; ok {
		t.Errorf("expected 'x-custom-header' to be deleted")
	}

	if got := h["Connection"]; len(got) != 1 || got[0] != "close" {
		t.Errorf("Connection = %v, want ['close']", got)
	}
	if got := h["Transfer-Encoding"]; len(got) != 1 || got[0] != "chunked" {
		t.Errorf("Transfer-Encoding = %v, want ['chunked']", got)
	}
	if got := h["X-Custom-Header"]; len(got) != 2 {
		t.Errorf("X-Custom-Header len = %d, want 2", len(got))
	}
}

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	h := http.Header{
		"connection": []string{"close"},
		"Connection": []string{"keep-alive"},
		"CONNECTION": []string{"foo"},
		"X-Keep":     []string{"bar"},
	}

	deleteHeaderCaseInsensitive(h, "Connection")

	for k := range h {
		if k != "X-Keep" {
			t.Errorf("unexpected key %q after deletion", k)
		}
	}
}

func TestPrepareRequestNonCanonicalHopByHopHeaders(t *testing.T) {
	handler := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header = http.Header{
		"connection":        []string{"close, x-custom-token"},
		"transfer-encoding": []string{"chunked"},
		"PROXY-CONNECTION":  []string{"close"},
		"Keep-Alive":        []string{"timeout=5"},
		"x-custom-token":    []string{"secret"},
		"X-CUSTOM-TOKEN":    []string{"secret2"},
		"x-app-header":      []string{"app-val"},
	}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	repl := caddy.NewReplacer()
	clonedReq, err := handler.prepareRequest(req, repl)
	if err != nil {
		t.Fatalf("prepareRequest failed: %v", err)
	}

	// Check that no hop-by-hop headers or connection-listed headers exist under any casing
	for k := range clonedReq.Header {
		switch k {
		case "connection", "Connection", "CONNECTION",
			"transfer-encoding", "Transfer-Encoding",
			"proxy-connection", "Proxy-Connection", "PROXY-CONNECTION",
			"keep-alive", "Keep-Alive",
			"x-custom-token", "X-Custom-Token", "X-CUSTOM-TOKEN":
			t.Errorf("hop-by-hop/connection header %q was not removed", k)
		}
	}

	if got := clonedReq.Header.Get("X-App-Header"); got != "app-val" {
		t.Errorf("X-App-Header = %q, want %q", got, "app-val")
	}
}

func TestPrepareRequestProtocolUpgradeNonCanonical(t *testing.T) {
	handler := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header = http.Header{
		"connection": []string{"upgrade"},
		"upgrade":    []string{"websocket"},
		"te":         []string{"trailers"},
	}

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	repl := caddy.NewReplacer()
	clonedReq, err := handler.prepareRequest(req, repl)
	if err != nil {
		t.Fatalf("prepareRequest failed: %v", err)
	}

	if got := clonedReq.Header.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q, want 'Upgrade'", got)
	}
	if got := clonedReq.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade = %q, want 'websocket'", got)
	}
	if got := clonedReq.Header.Get("Te"); got != "trailers" {
		t.Errorf("Te = %q, want 'trailers'", got)
	}
}

func TestFinalizeResponseNonCanonicalHopByHopHeaders(t *testing.T) {
	handler := Handler{}

	res := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader("")),
		Header: http.Header{
			"connection":         []string{"close, x-resp-token"},
			"transfer-encoding":  []string{"chunked"},
			"proxy-authenticate": []string{"Basic"},
			"x-resp-token":       []string{"secret"},
			"X-RESP-TOKEN":       []string{"secret2"},
			"x-resp-data":        []string{"data-val"},
		},
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	repl := caddy.NewReplacer()

	err := handler.finalizeResponse(rw, req, res, repl, time.Now(), zap.NewNop())
	if err != nil {
		t.Fatalf("finalizeResponse failed: %v", err)
	}

	outHeader := rw.Header()
	for k := range outHeader {
		switch k {
		case "connection", "Connection", "CONNECTION",
			"transfer-encoding", "Transfer-Encoding",
			"proxy-authenticate", "Proxy-Authenticate",
			"x-resp-token", "X-Resp-Token", "X-RESP-TOKEN":
			t.Errorf("response hop-by-hop/connection header %q was not removed", k)
		}
	}

	if got := outHeader.Get("X-Resp-Data"); got != "data-val" {
		t.Errorf("X-Resp-Data = %q, want %q", got, "data-val")
	}
}
