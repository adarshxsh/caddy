// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCopyResponseHeadersHandler_ServeHTTP_Canonicalization(t *testing.T) {
	nopNext := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	t.Run("include list with non-canonical upstream response headers", func(t *testing.T) {
		h := &CopyResponseHeadersHandler{
			Include: []string{"X-Request-Id", "Content-Type"},
		}
		if err := h.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}

		// Non-canonical header map
		respHeaders := http.Header{
			"x-request-id":      []string{"req-123"},
			"content-type":      []string{"application/json"},
			"x-unwanted-header": []string{"secret"},
		}

		hrc := &handleResponseContext{
			response: &http.Response{
				Header: respHeaders,
			},
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc))
		rw := httptest.NewRecorder()

		err := h.ServeHTTP(rw, req, nopNext)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}

		gotHeader := rw.Header()
		if got := gotHeader.Get("X-Request-Id"); got != "req-123" {
			t.Errorf("X-Request-Id = %q, want %q", got, "req-123")
		}
		if got := gotHeader.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
		if got := gotHeader.Get("X-Unwanted-Header"); got != "" {
			t.Errorf("X-Unwanted-Header should not be copied, got %q", got)
		}
	})

	t.Run("exclude list with non-canonical upstream response headers", func(t *testing.T) {
		h := &CopyResponseHeadersHandler{
			Exclude: []string{"Server", "X-Secret-Header"},
		}
		if err := h.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}

		// Non-canonical header map
		respHeaders := http.Header{
			"server":          []string{"nginx"},
			"x-secret-header": []string{"classified"},
			"x-request-id":    []string{"req-456"},
		}

		hrc := &handleResponseContext{
			response: &http.Response{
				Header: respHeaders,
			},
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc))
		rw := httptest.NewRecorder()

		err := h.ServeHTTP(rw, req, nopNext)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}

		gotHeader := rw.Header()
		if got := gotHeader.Get("Server"); got != "" {
			t.Errorf("Server should be excluded, got %q", got)
		}
		if got := gotHeader.Get("X-Secret-Header"); got != "" {
			t.Errorf("X-Secret-Header should be excluded, got %q", got)
		}
		if got := gotHeader.Get("X-Request-Id"); got != "req-456" {
			t.Errorf("X-Request-Id = %q, want %q", got, "req-456")
		}
	})

	t.Run("include with non-canonical filter config and mixed-case response header", func(t *testing.T) {
		h := &CopyResponseHeadersHandler{
			Include: []string{"x-request-id"},
		}
		if err := h.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision failed: %v", err)
		}

		respHeaders := http.Header{
			"X-Request-ID": []string{"req-789"},
		}

		hrc := &handleResponseContext{
			response: &http.Response{
				Header: respHeaders,
			},
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc))
		rw := httptest.NewRecorder()

		err := h.ServeHTTP(rw, req, nopNext)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}

		gotHeader := rw.Header()
		if got := gotHeader.Get("X-Request-Id"); got != "req-789" {
			t.Errorf("X-Request-Id = %q, want %q", got, "req-789")
		}
	})
}
