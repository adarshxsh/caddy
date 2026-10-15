package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestResponseTrailerPropagation(t *testing.T) {
	tests := []struct {
		name             string
		setupUpstream    func(w http.ResponseWriter)
		expectedTrailers http.Header
	}{
		{
			name: "preannounced response trailers",
			setupUpstream: func(w http.ResponseWriter) {
				w.Header().Set("Trailer", "At-End1, At-End2")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello trailer"))
				w.Header().Set(http.TrailerPrefix+"At-End1", "value1")
				w.Header().Set(http.TrailerPrefix+"At-End2", "value2")
			},
			expectedTrailers: http.Header{
				"At-End1": []string{"value1"},
				"At-End2": []string{"value2"},
			},
		},
		{
			name: "multiple values for trailer",
			setupUpstream: func(w http.ResponseWriter) {
				w.Header().Set("Trailer", "Multi-Val")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("multi val trailer"))
				w.Header().Add(http.TrailerPrefix+"Multi-Val", "val1")
				w.Header().Add(http.TrailerPrefix+"Multi-Val", "val2")
			},
			expectedTrailers: http.Header{
				"Multi-Val": []string{"val1", "val2"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.setupUpstream(w)
			}))
			defer upstream.Close()

			h := &Handler{
				logger: zap.NewNop(),
				Upstreams: []*Upstream{
					{Host: new(Host), Dial: upstream.Listener.Addr().String()},
				},
				LoadBalancing: &LoadBalancing{
					SelectionPolicy: &RandomSelection{},
				},
				Transport: &HTTPTransport{
					Transport: &http.Transport{},
				},
			}

			proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				repl := caddy.NewReplacer()
				r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
				_ = h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return nil
				}))
			}))
			defer proxyServer.Close()

			req, err := http.NewRequest(http.MethodGet, proxyServer.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to execute request: %v", err)
			}
			defer res.Body.Close()

			_, err = io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			for k, wantValues := range tc.expectedTrailers {
				gotValues := res.Trailer[k]
				if len(gotValues) != len(wantValues) {
					t.Errorf("trailer %s: got %v (len %d), want %v (len %d)", k, gotValues, len(gotValues), wantValues, len(wantValues))
					continue
				}
				for i := range wantValues {
					if gotValues[i] != wantValues[i] {
						t.Errorf("trailer %s[%d]: got %q, want %q", k, i, gotValues[i], wantValues[i])
					}
				}
			}
		})
	}
}
