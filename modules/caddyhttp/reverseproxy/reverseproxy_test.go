package reverseproxy

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestPrepareRequestEarlyData(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxy   bool
		is0RTT         bool
		isTLS          bool
		incomingHeader string
		wantHeader     string
	}{
		{
			name:           "untrusted client on standard HTTP request with spoofed header",
			trustedProxy:   false,
			isTLS:          false,
			is0RTT:         false,
			incomingHeader: "1",
			wantHeader:     "",
		},
		{
			name:           "untrusted client on completed TLS request with spoofed header",
			trustedProxy:   false,
			isTLS:          true,
			is0RTT:         false,
			incomingHeader: "1",
			wantHeader:     "",
		},
		{
			name:           "trusted proxy on standard HTTP request preserving Early-Data header",
			trustedProxy:   true,
			isTLS:          false,
			is0RTT:         false,
			incomingHeader: "1",
			wantHeader:     "1",
		},
		{
			name:           "untrusted client TLS 0-RTT sets Early-Data header",
			trustedProxy:   false,
			isTLS:          true,
			is0RTT:         true,
			incomingHeader: "",
			wantHeader:     "1",
		},
		{
			name:           "untrusted client TLS 0-RTT overwrites spoofed Early-Data header",
			trustedProxy:   false,
			isTLS:          true,
			is0RTT:         true,
			incomingHeader: "invalid",
			wantHeader:     "1",
		},
		{
			name:           "trusted proxy TLS 0-RTT sets Early-Data header",
			trustedProxy:   true,
			isTLS:          true,
			is0RTT:         true,
			incomingHeader: "",
			wantHeader:     "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{}

			url := "http://example.com/"
			if tt.isTLS {
				url = "https://example.com/"
			}

			req := httptest.NewRequest("GET", url, nil)
			if tt.incomingHeader != "" {
				req.Header.Set("Early-Data", tt.incomingHeader)
			}

			if tt.isTLS {
				req.TLS = &tls.ConnectionState{
					HandshakeComplete: !tt.is0RTT,
				}
			}

			vars := map[string]any{
				caddyhttp.TrustedProxyVarKey: tt.trustedProxy,
				caddyhttp.ClientIPVarKey:     "1.2.3.4",
			}
			ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)

			repl := caddy.NewReplacer()
			ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)

			preparedReq, err := h.prepareRequest(req, repl)
			if err != nil {
				t.Fatalf("unexpected error from prepareRequest: %v", err)
			}

			gotHeader := preparedReq.Header.Get("Early-Data")
			if gotHeader != tt.wantHeader {
				t.Errorf("Early-Data header = %q, want %q", gotHeader, tt.wantHeader)
			}
		})
	}
}
