package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestPreannouncedResponseTrailers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Test-Trailer, X-Second-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("streaming body content"))
		w.Header().Set("Trailer:X-Test-Trailer", "value1")
		w.Header().Set("Trailer:X-Second-Trailer", "value2")
	}))
	t.Cleanup(backend.Close)

	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := prepareTestRequest(r)
		_ = h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		}))
	}))
	t.Cleanup(proxy.Close)

	res, err := http.Get(proxy.URL)
	if err != nil {
		t.Fatalf("failed to GET from proxy: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if got, want := string(body), "streaming body content"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	if got, want := res.Trailer.Get("X-Test-Trailer"), "value1"; got != want {
		t.Errorf("X-Test-Trailer = %q, want %q", got, want)
	}
	if got, want := res.Trailer.Get("X-Second-Trailer"), "value2"; got != want {
		t.Errorf("X-Second-Trailer = %q, want %q", got, want)
	}
}

func TestResponseTrailersMultipleValues(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Multi-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("multi value content"))
		w.Header().Add("Trailer:X-Multi-Trailer", "val1")
		w.Header().Add("Trailer:X-Multi-Trailer", "val2")
	}))
	t.Cleanup(backend.Close)

	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()})

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := prepareTestRequest(r)
		_ = h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		}))
	}))
	t.Cleanup(proxy.Close)

	res, err := http.Get(proxy.URL)
	if err != nil {
		t.Fatalf("failed to GET from proxy: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if got, want := string(body), "multi value content"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	values := res.Trailer["X-Multi-Trailer"]
	if len(values) != 2 || values[0] != "val1" || values[1] != "val2" {
		t.Errorf("X-Multi-Trailer = %v, want %v", values, []string{"val1", "val2"})
	}
}
