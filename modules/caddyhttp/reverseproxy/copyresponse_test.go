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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCopyResponseHeadersHandler(t *testing.T) {
	tests := []struct {
		name              string
		handler           CopyResponseHeadersHandler
		upstreamHeader    http.Header
		expectedHeader    http.Header
		expectValidateErr bool
	}{
		{
			name: "include filter with non-canonical upstream headers",
			handler: CopyResponseHeadersHandler{
				Include: []string{"x-request-id", "X-Custom-Header"},
			},
			upstreamHeader: http.Header{
				"x-request-id":    []string{"req-123"},
				"x-custom-header": []string{"val1"},
				"other-header":    []string{"ignore"},
			},
			expectedHeader: http.Header{
				"X-Request-Id":    []string{"req-123"},
				"X-Custom-Header": []string{"val1"},
			},
		},
		{
			name: "exclude filter with non-canonical upstream headers",
			handler: CopyResponseHeadersHandler{
				Exclude: []string{"x-request-id", "content-type"},
			},
			upstreamHeader: http.Header{
				"x-request-id":    []string{"req-123"},
				"content-type":    []string{"application/json"},
				"x-custom-header": []string{"val1"},
			},
			expectedHeader: http.Header{
				"X-Custom-Header": []string{"val1"},
			},
		},
		{
			name: "no filter copies all headers with canonical keys",
			handler: CopyResponseHeadersHandler{},
			upstreamHeader: http.Header{
				"x-request-id":    []string{"req-123"},
				"x-custom-header": []string{"val1", "val2"},
			},
			expectedHeader: http.Header{
				"X-Request-Id":    []string{"req-123"},
				"X-Custom-Header": []string{"val1", "val2"},
			},
		},
		{
			name: "validation failure when both include and exclude defined",
			handler: CopyResponseHeadersHandler{
				Include: []string{"X-Request-ID"},
				Exclude: []string{"Server"},
			},
			expectValidateErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.handler.Validate()
			if tt.expectValidateErr {
				if err == nil {
					t.Fatalf("expected error from Validate(), got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error from Validate(): %v", err)
			}

			err = tt.handler.Provision(caddy.Context{})
			if err != nil {
				t.Fatalf("unexpected error from Provision(): %v", err)
			}

			hrc := &handleResponseContext{
				response: &http.Response{
					Header: tt.upstreamHeader,
				},
			}

			req := httptest.NewRequest("GET", "/", nil)
			ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			noopHandler := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) error {
				return nil
			})

			err = tt.handler.ServeHTTP(rec, req, noopHandler)
			if err != nil {
				t.Fatalf("unexpected error from ServeHTTP(): %v", err)
			}

			gotHeader := rec.Result().Header
			if !reflect.DeepEqual(gotHeader, tt.expectedHeader) {
				t.Errorf("header mismatch:\n got:  %v\n want: %v", gotHeader, tt.expectedHeader)
			}
		})
	}
}

func TestCopyResponseHeadersHandler_OutsideHandleResponseRoute(t *testing.T) {
	h := CopyResponseHeadersHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	noopHandler := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := h.ServeHTTP(rec, req, noopHandler)
	if err == nil {
		t.Fatal("expected error when running outside handle_response route, got nil")
	}
}

func TestCopyResponseHeadersStripsHopByHop(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h2="evil.example:443"; ma=86400`)
		w.Header().Set("Keep-Alive", "timeout=999")
		w.Header().Set("Proxy-Authenticate", `Basic realm="phish"`)
		w.Header().Set("X-Upstream", "kept")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "from-upstream")
	}))
	t.Cleanup(backend.Close)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	newHandler := func(t *testing.T, handles ...json.RawMessage) *Handler {
		t.Helper()
		h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})
		if len(handles) == 0 {
			return h
		}
		route := caddyhttp.Route{HandlersRaw: handles}
		if err := route.ProvisionHandlers(ctx, nil); err != nil {
			t.Fatalf("provision handle_response: %v", err)
		}
		h.HandleResponse = []caddyhttp.ResponseHandler{{
			Routes: caddyhttp.RouteList{route},
		}}
		return h
	}

	// The replacement body is the same length as the upstream body.
	// copy_response_headers also copies Content-Length, and a shorter
	// body makes the client report unexpected EOF. X-Replaced shows
	// that static_response ran.
	const replaced = `{"handler":"static_response","body":"from-upstream","headers":{"X-Replaced":["yes"]}}`
	cases := []struct {
		name        string
		handles     []json.RawMessage
		wantReplace bool
	}{
		{
			name: "default finalize",
		},
		{
			name: "copy_response",
			handles: []json.RawMessage{
				json.RawMessage(`{"handler":"copy_response"}`),
			},
		},
		{
			name: "copy_response_headers",
			handles: []json.RawMessage{
				json.RawMessage(`{"handler":"copy_response_headers"}`),
				json.RawMessage(replaced),
			},
			wantReplace: true,
		},
		{
			name: "include cannot copy hop-by-hop fields",
			handles: []json.RawMessage{
				json.RawMessage(`{"handler":"copy_response_headers","include":["Alt-Svc","X-Upstream","Keep-Alive"]}`),
				json.RawMessage(replaced),
			},
			wantReplace: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t, tc.handles...)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := h.ServeHTTP(w, prepareTestRequest(r), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					return nil
				}))
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
				}
			}))
			t.Cleanup(front.Close)

			resp, err := front.Client().Get(front.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
			}
			if string(body) != "from-upstream" {
				t.Fatalf("body = %q", body)
			}
			if got := resp.Header.Get("X-Upstream"); got != "kept" {
				t.Errorf("X-Upstream = %q, want kept", got)
			}
			if got, want := resp.Header.Get("X-Replaced") == "yes", tc.wantReplace; got != want {
				t.Errorf("X-Replaced present = %v, want %v", got, want)
			}
			for _, field := range []string{"Alt-Svc", "Keep-Alive", "Proxy-Authenticate"} {
				if got := resp.Header.Get(field); got != "" {
					t.Errorf("%s = %q, want absent", field, got)
				}
			}
		})
	}
}

func TestCopyResponseHeadersStripLeavesUpstreamHeader(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	h := &CopyResponseHeadersHandler{Include: []string{"Alt-Svc", "X-Upstream", "X-Hop"}}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	res := &http.Response{Header: make(http.Header), StatusCode: http.StatusOK}
	res.Header.Set("Alt-Svc", `h2="evil.example:443"`)
	res.Header.Set("X-Upstream", "kept")
	res.Header.Set("X-Hop", "secret")
	res.Header.Set("Connection", "close, X-Hop")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, &handleResponseContext{
		response: res,
	}))
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	if got := rec.Header().Get("X-Upstream"); got != "kept" {
		t.Errorf("X-Upstream = %q, want kept", got)
	}
	for _, field := range []string{"Alt-Svc", "X-Hop", "Connection"} {
		if got := rec.Header().Get(field); got != "" {
			t.Errorf("copied %s = %q, want absent", field, got)
		}
	}
	if got := res.Header.Get("Alt-Svc"); got != `h2="evil.example:443"` {
		t.Errorf("upstream Alt-Svc = %q, want it unchanged", got)
	}
	if got := res.Header.Get("X-Hop"); got != "secret" {
		t.Errorf("upstream X-Hop = %q, want it unchanged", got)
	}
	if got := res.Header.Get("Connection"); got != "close, X-Hop" {
		t.Errorf("upstream Connection = %q, want it unchanged", got)
	}
}
