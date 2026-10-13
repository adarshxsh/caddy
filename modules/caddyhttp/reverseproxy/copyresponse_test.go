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
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCopyResponseHeadersHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name            string
		include         []string
		exclude         []string
		upstreamHeaders http.Header
		expectedHeaders http.Header
		absentHeaders   []string
	}{
		{
			name:    "include non-canonical header keys from non-canonical include list",
			include: []string{"content-type", "x-custom-header"},
			upstreamHeaders: http.Header{
				"content-type":    []string{"application/json"},
				"x-custom-header": []string{"custom-value"},
				"x-ignored":       []string{"ignore-me"},
			},
			expectedHeaders: http.Header{
				"Content-Type":    []string{"application/json"},
				"X-Custom-Header": []string{"custom-value"},
			},
			absentHeaders: []string{"X-Ignored"},
		},
		{
			name:    "include canonical header keys from canonical include list",
			include: []string{"Content-Type", "X-Custom-Header"},
			upstreamHeaders: http.Header{
				"content-type":    []string{"application/json"},
				"x-custom-header": []string{"custom-value"},
				"x-ignored":       []string{"ignore-me"},
			},
			expectedHeaders: http.Header{
				"Content-Type":    []string{"application/json"},
				"X-Custom-Header": []string{"custom-value"},
			},
			absentHeaders: []string{"X-Ignored"},
		},
		{
			name:    "exclude non-canonical header keys from non-canonical exclude list",
			exclude: []string{"x-exclude-me", "server"},
			upstreamHeaders: http.Header{
				"x-exclude-me":  []string{"val1"},
				"server":        []string{"caddy"},
				"x-keep-header": []string{"keep-me"},
			},
			expectedHeaders: http.Header{
				"X-Keep-Header": []string{"keep-me"},
			},
			absentHeaders: []string{"X-Exclude-Me", "Server"},
		},
		{
			name:    "exclude non-canonical header keys from canonical exclude list",
			exclude: []string{"X-Exclude-Me", "Server"},
			upstreamHeaders: http.Header{
				"x-exclude-me":  []string{"val1"},
				"server":        []string{"caddy"},
				"x-keep-header": []string{"keep-me"},
			},
			expectedHeaders: http.Header{
				"X-Keep-Header": []string{"keep-me"},
			},
			absentHeaders: []string{"X-Exclude-Me", "Server"},
		},
		{
			name:    "no filters copies all headers",
			include: nil,
			exclude: nil,
			upstreamHeaders: http.Header{
				"x-header-one": []string{"v1"},
				"X-Header-Two": []string{"v2"},
			},
			expectedHeaders: http.Header{
				"X-Header-One": []string{"v1"},
				"X-Header-Two": []string{"v2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &CopyResponseHeadersHandler{
				Include: tt.include,
				Exclude: tt.exclude,
			}

			err := handler.Provision(caddy.Context{})
			if err != nil {
				t.Fatalf("unexpected provision error: %v", err)
			}

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			hrc := &handleResponseContext{
				response: &http.Response{
					Header: tt.upstreamHeaders,
				},
			}

			ctx := context.WithValue(req.Context(), proxyHandleResponseContextCtxKey, hrc)
			req = req.WithContext(ctx)

			next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
				return nil
			})

			err = handler.ServeHTTP(rw, req, next)
			if err != nil {
				t.Fatalf("unexpected ServeHTTP error: %v", err)
			}

			recHeader := rw.Header()

			for k, expectedVals := range tt.expectedHeaders {
				gotVals := recHeader.Values(k)
				if !reflect.DeepEqual(gotVals, expectedVals) {
					t.Errorf("header %q values = %v, expected %v", k, gotVals, expectedVals)
				}
			}

			for _, absentKey := range tt.absentHeaders {
				if gotVals := recHeader.Values(absentKey); len(gotVals) > 0 {
					t.Errorf("header %q should be absent, but got %v", absentKey, gotVals)
				}
			}
		})
	}
}

func TestCopyResponseHeadersHandler_ErrorOutsideRoute(t *testing.T) {
	handler := &CopyResponseHeadersHandler{}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
		return nil
	})

	err := handler.ServeHTTP(rw, req, next)
	if err == nil {
		t.Fatal("expected error when running outside reverse_proxy handle_response context, got nil")
	}
}
