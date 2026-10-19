package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCopyResponseHeadersHandler_ServeHTTP_Include(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Include: []string{"x-request-id", "X-Custom-Header"},
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	upstreamHeader := http.Header{
		"x-request-id":    []string{"req-123"},
		"x-custom-header": []string{"val1", "val2"},
		"x-ignored":       []string{"should-be-ignored"},
	}

	hrc := &handleResponseContext{
		response: &http.Response{
			Header: upstreamHeader,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()

	if got := resHeader.Values("X-Request-Id"); !reflect.DeepEqual(got, []string{"req-123"}) {
		t.Errorf("X-Request-Id = %v, want %v", got, []string{"req-123"})
	}

	if got := resHeader.Values("X-Custom-Header"); !reflect.DeepEqual(got, []string{"val1", "val2"}) {
		t.Errorf("X-Custom-Header = %v, want %v", got, []string{"val1", "val2"})
	}

	if got := resHeader.Values("X-Ignored"); len(got) > 0 {
		t.Errorf("X-Ignored should not be copied, got %v", got)
	}
}

func TestCopyResponseHeadersHandler_ServeHTTP_Exclude(t *testing.T) {
	h := CopyResponseHeadersHandler{
		Exclude: []string{"x-sensitive-token", "X-Secret"},
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	upstreamHeader := http.Header{
		"x-sensitive-token": []string{"secret123"},
		"x-secret":          []string{"topsecret"},
		"x-allowed-header":  []string{"allowed"},
	}

	hrc := &handleResponseContext{
		response: &http.Response{
			Header: upstreamHeader,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	resHeader := rec.Header()

	if got := resHeader.Values("X-Allowed-Header"); !reflect.DeepEqual(got, []string{"allowed"}) {
		t.Errorf("X-Allowed-Header = %v, want %v", got, []string{"allowed"})
	}

	if got := resHeader.Values("X-Sensitive-Token"); len(got) > 0 {
		t.Errorf("X-Sensitive-Token should be excluded, got %v", got)
	}

	if got := resHeader.Values("X-Secret"); len(got) > 0 {
		t.Errorf("X-Secret should be excluded, got %v", got)
	}
}

func TestCopyResponseHeadersHandler_ServeHTTP_OutsideHandleResponse(t *testing.T) {
	h := CopyResponseHeadersHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	err := h.ServeHTTP(rec, req, next)
	if err == nil {
		t.Fatalf("expected error when running outside handle_response routes, got nil")
	}
}
