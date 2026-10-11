package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCopyResponseHeadersHandler_Include(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Include: []string{"x-foo-bar", "X-Included-Header"},
	}
	err := h.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	hrc := &handleResponseContext{
		response: &http.Response{
			Header: http.Header{
				"x-foo-bar":         []string{"val1"},
				"X-INCLUDED-HEADER": []string{"val2"},
				"x-omitted-header":  []string{"val3"},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	noopHandler := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	err = h.ServeHTTP(rec, req, noopHandler)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()

	if got := resHeader.Get("X-Foo-Bar"); got != "val1" {
		t.Errorf("expected X-Foo-Bar = val1, got %q", got)
	}
	if got := resHeader.Get("X-Included-Header"); got != "val2" {
		t.Errorf("expected X-Included-Header = val2, got %q", got)
	}
	if got := resHeader.Get("X-Omitted-Header"); got != "" {
		t.Errorf("expected X-Omitted-Header to be omitted, got %q", got)
	}
}

func TestCopyResponseHeadersHandler_Exclude(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Exclude: []string{"x-sensitive-token", "X-Excluded-Header"},
	}
	err := h.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	hrc := &handleResponseContext{
		response: &http.Response{
			Header: http.Header{
				"X-SENSITIVE-TOKEN": []string{"secret"},
				"x-excluded-header": []string{"skip"},
				"x-allowed-header":  []string{"keep"},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	noopHandler := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	err = h.ServeHTTP(rec, req, noopHandler)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()

	if got := resHeader.Get("X-Sensitive-Token"); got != "" {
		t.Errorf("expected X-Sensitive-Token to be excluded, got %q", got)
	}
	if got := resHeader.Get("X-Excluded-Header"); got != "" {
		t.Errorf("expected X-Excluded-Header to be excluded, got %q", got)
	}
	if got := resHeader.Get("X-Allowed-Header"); got != "keep" {
		t.Errorf("expected X-Allowed-Header = keep, got %q", got)
	}
}
