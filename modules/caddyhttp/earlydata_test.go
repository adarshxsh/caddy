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

package caddyhttp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testMiddlewareHandler func(w http.ResponseWriter, r *http.Request, next Handler) error

func (f testMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	return f(w, r, next)
}

func TestEarlyDataMethodGuard(t *testing.T) {
	handlerExecuted := false
	handler := testMiddlewareHandler(func(w http.ResponseWriter, r *http.Request, next Handler) error {
		handlerExecuted = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	srv := &Server{
		Routes: RouteList{
			Route{
				Handlers: []MiddlewareHandler{handler},
			},
		},
	}
	require.NoError(t, srv.Routes.ProvisionHandlers(caddy.Context{}, nil))

	tests := []struct {
		name              string
		method            string
		handshakeComplete bool
		isTLS             bool
		expectedStatus    int
		expectedHeader    string
		expectHandlerExec bool
	}{
		{
			name:              "0-RTT GET request (safe method)",
			method:            http.MethodGet,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
		{
			name:              "0-RTT HEAD request (safe method)",
			method:            http.MethodHead,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
		{
			name:              "0-RTT OPTIONS request (safe method)",
			method:            http.MethodOptions,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
		{
			name:              "0-RTT TRACE request (safe method)",
			method:            "TRACE",
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
		{
			name:              "0-RTT POST request (unsafe method) rejected",
			method:            http.MethodPost,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusTooEarly,
			expectedHeader:    "1",
			expectHandlerExec: false,
		},
		{
			name:              "0-RTT PUT request (unsafe method) rejected",
			method:            http.MethodPut,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusTooEarly,
			expectedHeader:    "1",
			expectHandlerExec: false,
		},
		{
			name:              "0-RTT DELETE request (unsafe method) rejected",
			method:            http.MethodDelete,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusTooEarly,
			expectedHeader:    "1",
			expectHandlerExec: false,
		},
		{
			name:              "0-RTT PATCH request (unsafe method) rejected",
			method:            http.MethodPatch,
			handshakeComplete: false,
			isTLS:             true,
			expectedStatus:    http.StatusTooEarly,
			expectedHeader:    "1",
			expectHandlerExec: false,
		},
		{
			name:              "1-RTT POST request (handshake complete) allowed",
			method:            http.MethodPost,
			handshakeComplete: true,
			isTLS:             true,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
		{
			name:              "Plain HTTP POST request allowed",
			method:            http.MethodPost,
			handshakeComplete: false,
			isTLS:             false,
			expectedStatus:    http.StatusOK,
			expectedHeader:    "",
			expectHandlerExec: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerExecuted = false
			req := httptest.NewRequest(tt.method, "/", nil)
			if tt.isTLS {
				req.TLS = &tls.ConnectionState{
					HandshakeComplete: tt.handshakeComplete,
				}
			}

			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, tt.expectedHeader, rec.Header().Get("Too-Early"))
			assert.Equal(t, tt.expectHandlerExec, handlerExecuted)
		})
	}
}

func TestEarlyDataPolicies(t *testing.T) {
	t.Run("server policy allow", func(t *testing.T) {
		handlerExecuted := false
		srv := &Server{
			EarlyData: "allow",
			Routes: RouteList{
				Route{
					Handlers: []MiddlewareHandler{
						testMiddlewareHandler(func(w http.ResponseWriter, r *http.Request, next Handler) error {
							handlerExecuted = true
							w.WriteHeader(http.StatusOK)
							return nil
						}),
					},
				},
			},
		}
		require.NoError(t, srv.Routes.ProvisionHandlers(caddy.Context{}, nil))

		req := httptest.NewRequest(http.MethodPost, "/api/create", nil)
		req.TLS = &tls.ConnectionState{HandshakeComplete: false}
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerExecuted)
	})

	t.Run("server policy deny", func(t *testing.T) {
		handlerExecuted := false
		srv := &Server{
			EarlyData: "deny",
			Routes: RouteList{
				Route{
					Handlers: []MiddlewareHandler{
						testMiddlewareHandler(func(w http.ResponseWriter, r *http.Request, next Handler) error {
							handlerExecuted = true
							w.WriteHeader(http.StatusOK)
							return nil
						}),
					},
				},
			},
		}
		require.NoError(t, srv.Routes.ProvisionHandlers(caddy.Context{}, nil))

		req := httptest.NewRequest(http.MethodGet, "/static/file.js", nil)
		req.TLS = &tls.ConnectionState{HandshakeComplete: false}
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooEarly, rec.Code)
		assert.Equal(t, "1", rec.Header().Get("Too-Early"))
		assert.False(t, handlerExecuted)
	})

	t.Run("route policy override allow on specific route", func(t *testing.T) {
		handler1Executed := false
		handler2Executed := false

		srv := &Server{
			Routes: RouteList{
				Route{
					EarlyData: "allow",
					MatcherSets: MatcherSets{
						MatcherSet{MatchPath{"/custom-replay/*"}},
					},
					Handlers: []MiddlewareHandler{
						testMiddlewareHandler(func(w http.ResponseWriter, r *http.Request, next Handler) error {
							handler1Executed = true
							w.WriteHeader(http.StatusOK)
							return nil
						}),
					},
				},
				Route{
					MatcherSets: MatcherSets{
						MatcherSet{MatchPath{"/strict/*"}},
					},
					Handlers: []MiddlewareHandler{
						testMiddlewareHandler(func(w http.ResponseWriter, r *http.Request, next Handler) error {
							handler2Executed = true
							w.WriteHeader(http.StatusOK)
							return nil
						}),
					},
				},
			},
		}
		require.NoError(t, srv.Routes.ProvisionHandlers(caddy.Context{}, nil))

		// Request to /custom-replay/post (route policy allow) -> should succeed
		req1 := httptest.NewRequest(http.MethodPost, "/custom-replay/post", nil)
		req1.TLS = &tls.ConnectionState{HandshakeComplete: false}
		rec1 := httptest.NewRecorder()
		srv.ServeHTTP(rec1, req1)

		assert.Equal(t, http.StatusOK, rec1.Code)
		assert.True(t, handler1Executed)

		// Request to /strict/post (default policy safe_only) -> should be rejected with 425
		req2 := httptest.NewRequest(http.MethodPost, "/strict/post", nil)
		req2.TLS = &tls.ConnectionState{HandshakeComplete: false}
		rec2 := httptest.NewRecorder()
		srv.ServeHTTP(rec2, req2)

		assert.Equal(t, http.StatusTooEarly, rec2.Code)
		assert.Equal(t, "1", rec2.Header().Get("Too-Early"))
		assert.False(t, handler2Executed)
	})
}

func TestEarlyDataCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`early_data deny`)
	ed := new(EarlyData)
	err := ed.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	assert.Equal(t, "deny", ed.Policy)

	d2 := caddyfile.NewTestDispenser(`early_data allow`)
	ed2 := new(EarlyData)
	err = ed2.UnmarshalCaddyfile(d2)
	require.NoError(t, err)
	assert.Equal(t, "allow", ed2.Policy)
}
