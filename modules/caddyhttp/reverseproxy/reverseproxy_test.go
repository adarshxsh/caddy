package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	h := http.Header{
		"Connection": []string{"close"},
		"connection": []string{"keep-alive"},
		"CoNnEcTiOn": []string{"Upgrade"},
		"Foo":        []string{"bar"},
	}

	deleteHeaderCaseInsensitive(h, "CONNECTION")

	if len(getHeaderValuesCaseInsensitive(h, "connection")) != 0 {
		t.Errorf("expected all connection headers to be deleted, got %v", h)
	}
	if got := h.Get("Foo"); got != "bar" {
		t.Errorf("expected Foo header to remain, got %q", got)
	}
}

func TestGetHeaderValuesCaseInsensitive(t *testing.T) {
	h := http.Header{
		"Connection": []string{"close"},
		"connection": []string{"keep-alive"},
		"CoNnEcTiOn": []string{"Upgrade"},
	}

	vals := getHeaderValuesCaseInsensitive(h, "connection")
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d: %v", len(vals), vals)
	}
}

func TestGetHeaderCaseInsensitive(t *testing.T) {
	h := http.Header{
		"upgrade": []string{"websocket"},
	}

	val := getHeaderCaseInsensitive(h, "Upgrade")
	if val != "websocket" {
		t.Errorf("expected websocket, got %q", val)
	}
}

func TestUpgradeTypeCaseInsensitive(t *testing.T) {
	h := http.Header{
		"cOnNeCtIoN": []string{"uPgRaDe"},
		"UPGRADE":    []string{"Websocket"},
	}

	got := upgradeType(h)
	if got != "websocket" {
		t.Errorf("upgradeType = %q, want %q", got, "websocket")
	}
}

func TestRemoveConnectionHeadersCaseInsensitive(t *testing.T) {
	h := http.Header{
		"cOnNeCtIoN":     []string{"x-custom-header, keep-alive", "y-custom-header"},
		"X-Custom-Header": []string{"val1"},
		"x-custom-header": []string{"val2"},
		"Y-CUSTOM-HEADER": []string{"val3"},
		"Keep-Alive":      []string{"timeout=5"},
		"X-Keep-Header":   []string{"stay"},
	}

	removeConnectionHeaders(h)

	for _, name := range []string{"X-Custom-Header", "Y-Custom-Header", "Keep-Alive"} {
		if vals := getHeaderValuesCaseInsensitive(h, name); len(vals) > 0 {
			t.Errorf("expected header %q to be deleted by removeConnectionHeaders, found: %v", name, vals)
		}
	}

	if got := h.Get("X-Keep-Header"); got != "stay" {
		t.Errorf("X-Keep-Header = %q, want %q", got, "stay")
	}
}

func TestNonCanonicalHopByHopHeaderStripping(t *testing.T) {
	handler := &Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	vars := map[string]any{
		caddyhttp.ClientIPVarKey:     "127.0.0.1",
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)
	req.Header["alt-svc"] = []string{"h3=\":443\""}
	req.Header["connection"] = []string{"x-foo, close"}
	req.Header["x-foo"] = []string{"bar"}
	req.Header["proxy-connection"] = []string{"close"}
	req.Header["keep-alive"] = []string{"timeout=5"}
	req.Header["proxy-authenticate"] = []string{"Basic"}
	req.Header["proxy-authorization"] = []string{"Basic xyz"}
	req.Header["te"] = []string{"trailers, deflate"}
	req.Header["trailer"] = []string{"X-Trailer"}
	req.Header["transfer-encoding"] = []string{"chunked"}
	req.Header["upgrade"] = []string{"foo"}
	req.Header["x-normal-header"] = []string{"keep-me"}

	repl := caddy.NewReplacer()
	clonedReq, err := handler.prepareRequest(req, repl)
	if err != nil {
		t.Fatalf("prepareRequest error: %v", err)
	}

	nonCanonicalHopHeaders := []string{
		"alt-svc",
		"connection",
		"x-foo",
		"proxy-connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"trailer",
		"transfer-encoding",
		"upgrade",
	}

	for _, h := range nonCanonicalHopHeaders {
		if vals := getHeaderValuesCaseInsensitive(clonedReq.Header, h); len(vals) > 0 {
			t.Errorf("expected request header %q to be stripped, got %v", h, vals)
		}
	}

	if got := getHeaderCaseInsensitive(clonedReq.Header, "X-Normal-Header"); got != "keep-me" {
		t.Errorf("X-Normal-Header = %q, want %q", got, "keep-me")
	}

	if got := getHeaderCaseInsensitive(clonedReq.Header, "Te"); got != "trailers" {
		t.Errorf("Te = %q, want %q", got, "trailers")
	}
}

func TestResponseNonCanonicalHopByHopHeaderStripping(t *testing.T) {
	res := &http.Response{
		Header: make(http.Header),
	}

	res.Header["connection"] = []string{"x-res-custom"}
	res.Header["x-res-custom"] = []string{"secret"}
	res.Header["transfer-encoding"] = []string{"chunked"}
	res.Header["upgrade"] = []string{"h2c"}
	res.Header["x-valid-res-header"] = []string{"ok"}

	removeConnectionHeaders(res.Header)
	for _, h := range hopHeaders {
		deleteHeaderCaseInsensitive(res.Header, h)
	}

	for _, h := range []string{"connection", "x-res-custom", "transfer-encoding", "upgrade"} {
		if vals := getHeaderValuesCaseInsensitive(res.Header, h); len(vals) > 0 {
			t.Errorf("expected response header %q to be stripped, got %v", h, vals)
		}
	}

	if got := getHeaderCaseInsensitive(res.Header, "X-Valid-Res-Header"); got != "ok" {
		t.Errorf("X-Valid-Res-Header = %q, want %q", got, "ok")
	}
}
