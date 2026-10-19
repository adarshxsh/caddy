package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

type healthCheckTestTransport struct {
	gotReq *http.Request
}

func (tt *healthCheckTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tt.gotReq = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func TestActiveHealthCheckHostHeaderCase(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantHost   string
	}{
		{
			name: "canonical Host header",
			headers: http.Header{
				"Host": []string{"example.com"},
			},
			wantHost: "example.com",
		},
		{
			name: "lowercase host header",
			headers: http.Header{
				"host": []string{"example.com"},
			},
			wantHost: "example.com",
		},
		{
			name: "uppercase HOST header",
			headers: http.Header{
				"HOST": []string{"example.com"},
			},
			wantHost: "example.com",
		},
		{
			name: "mixed case hOsT header",
			headers: http.Header{
				"hOsT": []string{"example.com"},
			},
			wantHost: "example.com",
		},
		{
			name: "empty host value slice",
			headers: http.Header{
				"host": []string{},
			},
			wantHost: "127.0.0.1:8080", // Default Host derived from URL
		},
		{
			name: "custom header with non-canonical host header",
			headers: http.Header{
				"host":         []string{"example.com"},
				"X-Custom-Hdr": []string{"custom-value"},
			},
			wantHost: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &healthCheckTestTransport{}
			h := &Handler{
				ctx: caddy.Context{Context: context.Background()},
				HealthChecks: &HealthChecks{
					Active: &ActiveHealthChecks{
						Headers:    tt.headers,
						httpClient: &http.Client{Transport: transport},
					},
				},
			}

			upstream := &Upstream{
				Dial: "127.0.0.1:8080",
				Host: &Host{},
			}

			err := h.doActiveHealthCheck(DialInfo{}, "127.0.0.1:8080", "127.0.0.1:8080", upstream)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if transport.gotReq == nil {
				t.Fatalf("expected request to be made")
			}

			if transport.gotReq.Host != tt.wantHost {
				t.Errorf("req.Host = %q, want %q", transport.gotReq.Host, tt.wantHost)
			}

			// Verify that Host header was not set in req.Header
			for k := range transport.gotReq.Header {
				if strings.EqualFold(k, "Host") {
					t.Errorf("req.Header contains %q = %v, but Host should be set on req.Host instead", k, transport.gotReq.Header[k])
				}
			}

			if tt.headers.Get("X-Custom-Hdr") != "" {
				if got := transport.gotReq.Header.Get("X-Custom-Hdr"); got != "custom-value" {
					t.Errorf("req.Header.Get(\"X-Custom-Hdr\") = %q, want %q", got, "custom-value")
				}
			}
		})
	}
}
