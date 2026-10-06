package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestSelectiveHeaderClearing1xx(t *testing.T) {
	// 1. Setup backend server that emits 103 Early Hints and then 200 OK
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.Header().Set("X-Shared", "1xx-shared")
		w.WriteHeader(http.StatusEarlyHints)

		// Backend removes 1xx-specific headers before writing final 200 OK
		w.Header().Del("Link")
		w.Header().Del("X-Shared")
		w.Header().Set("X-200", "ok-val")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	upstream := &Upstream{
		Dial: backend.Listener.Addr().String(),
		Host: new(Host),
	}

	h := &Handler{
		logger:        zap.NewNop(),
		Transport:     testTransport{&http.Transport{}},
		Upstreams:     []*Upstream{upstream},
		LoadBalancing: &LoadBalancing{SelectionPolicy: &RoundRobinSelection{}},
	}

	// 2. Wrap proxy handler in a test server to use real http.ResponseWriter
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := prepareTestRequest(r)
		// Outer middleware sets downstream response headers before proxying
		w.Header().Set("X-Outer-Header", "outer-val")
		w.Header().Set("X-Shared", "outer-shared")

		_ = h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		}))
	}))
	defer proxyServer.Close()

	// 3. Make client request to proxy server
	res, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("unexpected error on GET: %v", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if string(body) != "OK" {
		t.Errorf("body = %q, want %q", string(body), "OK")
	}

	// 4. Verify outer middleware headers persist in final response
	if got := res.Header.Get("X-Outer-Header"); got != "outer-val" {
		t.Errorf("X-Outer-Header = %q, want %q", got, "outer-val")
	}

	// 5. Verify pre-existing outer header value was restored over 1xx header value
	if got := res.Header.Get("X-Shared"); got != "outer-shared" {
		t.Errorf("X-Shared = %q, want %q", got, "outer-shared")
	}

	// 6. Verify main 200 response header is present
	if got := res.Header.Get("X-200"); got != "ok-val" {
		t.Errorf("X-200 = %q, want %q", got, "ok-val")
	}

	// 7. Verify 1xx-only header did NOT spill over into final response
	if got := res.Header.Get("Link"); got != "" {
		t.Errorf("Link header should not spill into final response, got %q", got)
	}
}

func TestMultiple1xxResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-100", "100-val")
		w.WriteHeader(http.StatusContinue)

		w.Header().Set("Link", "</script.js>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)

		w.Header().Del("X-100")
		w.Header().Del("Link")
		w.Header().Set("X-Final", "final-val")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DONE"))
	}))
	defer backend.Close()

	upstream := &Upstream{
		Dial: backend.Listener.Addr().String(),
		Host: new(Host),
	}

	h := &Handler{
		logger:        zap.NewNop(),
		Transport:     testTransport{&http.Transport{}},
		Upstreams:     []*Upstream{upstream},
		LoadBalancing: &LoadBalancing{SelectionPolicy: &RoundRobinSelection{}},
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := prepareTestRequest(r)
		w.Header().Set("X-Outer-Tracing", "trace-123")

		_ = h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		}))
	}))
	defer proxyServer.Close()

	res, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("unexpected error on GET: %v", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if string(body) != "DONE" {
		t.Errorf("body = %q, want %q", string(body), "DONE")
	}

	if got := res.Header.Get("X-Outer-Tracing"); got != "trace-123" {
		t.Errorf("X-Outer-Tracing = %q, want %q", got, "trace-123")
	}
	if got := res.Header.Get("X-Final"); got != "final-val" {
		t.Errorf("X-Final = %q, want %q", got, "final-val")
	}
	if got := res.Header.Get("X-100"); got != "" {
		t.Errorf("X-100 should not spill into final response, got %q", got)
	}
	if got := res.Header.Get("Link"); got != "" {
		t.Errorf("Link should not spill into final response, got %q", got)
	}
}

func TestGot1xxResponseSelectiveRemoval(t *testing.T) {
	rec := httptest.NewRecorder()
	h := rec.Header()

	// Outer middleware pre-sets headers
	h.Set("X-Outer-Key", "outer-val")
	h.Set("X-Overlap", "outer-overlap")

	// Simulate 1xx response trace callback
	mimeHeader := textproto.MIMEHeader{
		"Link":      []string{"</style.css>; rel=preload"},
		"X-Overlap": []string{"1xx-overlap"},
	}

	// Re-create trace callback logic to test directly
	type preExistingHeader struct {
		rawKey string
		values []string
		exists bool
	}
	saved := make(map[string]preExistingHeader, len(mimeHeader))
	for k := range mimeHeader {
		ck := http.CanonicalHeaderKey(k)
		if _, processed := saved[ck]; processed {
			continue
		}
		val, exists := h[ck]
		rawKey := ck
		if !exists && ck != k {
			val, exists = h[k]
			if exists {
				rawKey = k
			}
		}
		if exists {
			valCopy := append([]string(nil), val...)
			saved[ck] = preExistingHeader{rawKey: rawKey, values: valCopy, exists: true}
		} else {
			saved[ck] = preExistingHeader{rawKey: rawKey, values: nil, exists: false}
		}
	}

	// Copy 1xx headers and write 1xx status code
	copyHeader(h, http.Header(mimeHeader))
	rec.WriteHeader(103)

	// Restore / clean up 1xx headers
	for ck, item := range saved {
		if item.exists {
			h[ck] = item.values
			if item.rawKey != ck {
				delete(h, item.rawKey)
			}
		} else {
			delete(h, ck)
			delete(h, item.rawKey)
		}
	}

	// Verify header map state
	if got := h.Get("X-Outer-Key"); got != "outer-val" {
		t.Errorf("X-Outer-Key = %q, want %q", got, "outer-val")
	}
	if got := h.Get("X-Overlap"); got != "outer-overlap" {
		t.Errorf("X-Overlap = %q, want %q", got, "outer-overlap")
	}
	if got := h.Get("Link"); got != "" {
		t.Errorf("Link header should have been deleted, got %q", got)
	}
}
