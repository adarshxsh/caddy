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
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestActiveHealthCheckHostHeader(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		callProvision bool
		expectedHost  string
	}{
		{
			name:          "canonical Host header",
			headers:       http.Header{"Host": []string{"example.com"}},
			callProvision: false,
			expectedHost:  "example.com",
		},
		{
			name:          "lowercase host header without provision",
			headers:       http.Header{"host": []string{"example.com"}},
			callProvision: false,
			expectedHost:  "example.com",
		},
		{
			name:          "lowercase host header with provision",
			headers:       http.Header{"host": []string{"example.com"}},
			callProvision: true,
			expectedHost:  "example.com",
		},
		{
			name:          "uppercase HOST header",
			headers:       http.Header{"HOST": []string{"example.com"}},
			callProvision: false,
			expectedHost:  "example.com",
		},
		{
			name:          "mixed case hOsT header",
			headers:       http.Header{"hOsT": []string{"example.com"}},
			callProvision: false,
			expectedHost:  "example.com",
		},
		{
			name:          "host header with placeholder",
			headers:       http.Header{"host": []string{"{env.TEST_HOST_VAL}"}},
			callProvision: false,
			expectedHost:  "placeholder.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "host header with placeholder" {
				t.Setenv("TEST_HOST_VAL", "placeholder.example.com")
			}

			caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			var capturedReq *http.Request
			client := &http.Client{
				Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
					capturedReq = req
					rec := httptest.NewRecorder()
					rec.WriteHeader(http.StatusOK)
					return rec.Result(), nil
				}),
			}

			active := &ActiveHealthChecks{
				Headers:    tt.headers,
				httpClient: client,
			}

			h := &Handler{
				ctx:    caddyCtx,
				logger: zap.NewNop(),
				HealthChecks: &HealthChecks{
					Active: active,
				},
			}

			if tt.callProvision {
				// URI or Path must be set for IsEnabled to return true during Provision
				active.URI = "/health"
				err := active.Provision(caddyCtx, h)
				if err != nil {
					t.Fatalf("Provision failed: %v", err)
				}
				// Re-assign custom transport client since Provision overrides httpClient
				active.httpClient = client
			}

			u := &Upstream{
				Dial: "127.0.0.1:8080",
				Host: new(Host),
			}

			dialInfo := DialInfo{
				Network: "tcp",
				Address: "127.0.0.1:8080",
			}

			err := h.doActiveHealthCheck(dialInfo, "127.0.0.1:8080", "127.0.0.1:8080", u)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if capturedReq == nil {
				t.Fatal("expected request to be captured, got nil")
			}

			if capturedReq.Host != tt.expectedHost {
				t.Errorf("expected req.Host %q, got %q", tt.expectedHost, capturedReq.Host)
			}

			// Ensure Host/host/HOST is not placed in req.Header map
			for k := range capturedReq.Header {
				if strings.EqualFold(k, "Host") {
					t.Errorf("Host header key %q should not be in req.Header, found values: %v", k, capturedReq.Header[k])
				}
			}
		})
	}
}
