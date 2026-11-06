package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestResponseTrailers(t *testing.T) {
	tests := []struct {
		name           string
		preannounce    []string
		trailers       map[string][]string
		wantBody       string
		expectedResult map[string][]string
	}{
		{
			name:        "preannounced trailers (grpc-status, server-timing)",
			preannounce: []string{"Grpc-Status", "Server-Timing"},
			trailers: map[string][]string{
				"Grpc-Status":   {"0"},
				"Server-Timing": {"app;dur=42"},
			},
			wantBody: "hello preannounced trailers",
			expectedResult: map[string][]string{
				"Grpc-Status":   {"0"},
				"Server-Timing": {"app;dur=42"},
			},
		},
		{
			name:        "multiple trailer values",
			preannounce: []string{"X-Multi-Trailer"},
			trailers: map[string][]string{
				"X-Multi-Trailer": {"val1", "val2"},
			},
			wantBody: "hello multi trailers",
			expectedResult: map[string][]string{
				"X-Multi-Trailer": {"val1", "val2"},
			},
		},
		{
			name:        "empty trailer value",
			preannounce: []string{"Empty-Header"},
			trailers: map[string][]string{
				"Empty-Header": {""},
			},
			wantBody: "hello empty trailer",
			expectedResult: map[string][]string{
				"Empty-Header": {""},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, p := range tc.preannounce {
					w.Header().Add("Trailer", p)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.wantBody))
				for k, vv := range tc.trailers {
					for _, v := range vv {
						w.Header().Add(http.TrailerPrefix+k, v)
					}
				}
			}))
			defer backend.Close()

			upstream := &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()}
			h := minimalHandler(0, upstream)

			proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = prepareTestRequest(r)

				err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return nil
				}))
				if err != nil {
					t.Errorf("ServeHTTP error: %v", err)
				}
			}))
			defer proxyServer.Close()

			resp, err := http.Get(proxyServer.URL)
			if err != nil {
				t.Fatalf("GET request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll body failed: %v", err)
			}
			if string(body) != tc.wantBody {
				t.Errorf("body = %q, want %q", string(body), tc.wantBody)
			}

			for k, wantVals := range tc.expectedResult {
				gotVals := resp.Trailer[k]
				if len(gotVals) != len(wantVals) {
					t.Fatalf("Trailer %s count = %d, want %d (got %v, want %v)", k, len(gotVals), len(wantVals), gotVals, wantVals)
				}
				for i, wantVal := range wantVals {
					if gotVals[i] != wantVal {
						t.Errorf("Trailer %s[%d] = %q, want %q", k, i, gotVals[i], wantVal)
					}
				}
			}
		})
	}
}
