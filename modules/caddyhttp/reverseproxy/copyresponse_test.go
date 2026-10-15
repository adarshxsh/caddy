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
