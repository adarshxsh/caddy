package reverseproxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type trackingResponseWriter struct {
	http.ResponseWriter
	mu            sync.Mutex
	writtenCodes  []int
	writtenHeader []http.Header
}

func newTrackingResponseWriter(rw http.ResponseWriter) *trackingResponseWriter {
	return &trackingResponseWriter{
		ResponseWriter: rw,
	}
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	w.writtenCodes = append(w.writtenCodes, code)
	w.writtenHeader = append(w.writtenHeader, w.ResponseWriter.Header().Clone())
	w.mu.Unlock()
	w.ResponseWriter.WriteHeader(code)
}

func Test1xxPreservesDownstreamHeaders(t *testing.T) {
	// Setup backend server that emits a 103 Early Hints informational response
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Setup reverse proxy handler targeting backend
	upstream := &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()}
	handler := minimalHandler(0, upstream)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	tracker := newTrackingResponseWriter(rec)

	// Set outer middleware downstream header before reverse proxy executes
	tracker.Header().Set("X-Outer-Middleware", "present-value")
	tracker.Header().Set("X-Trace-ID", "12345")

	err := handler.ServeHTTP(tracker, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// 1. Verify outer middleware headers are present in the final response
	if got := tracker.Header().Get("X-Outer-Middleware"); got != "present-value" {
		t.Errorf("Final response missing X-Outer-Middleware header; got %q, want %q", got, "present-value")
	}
	if got := tracker.Header().Get("X-Trace-ID"); got != "12345" {
		t.Errorf("Final response missing X-Trace-ID header; got %q, want %q", got, "12345")
	}

	// 2. Verify final response has backend final header
	if got := tracker.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Final response missing Content-Type; got %q, want %q", got, "text/plain")
	}

	// 3. Verify upstream 1xx header drops from final response header map
	if got := tracker.Header().Get("Link"); got != "" {
		t.Errorf("Final response should not contain upstream 1xx header 'Link'; got %q", got)
	}

	// 4. Verify status codes written
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if len(tracker.writtenCodes) < 2 {
		t.Fatalf("Expected at least 2 WriteHeader calls (1xx and final), got %d: %v", len(tracker.writtenCodes), tracker.writtenCodes)
	}

	// First WriteHeader should be 103 Early Hints
	if tracker.writtenCodes[0] != http.StatusEarlyHints {
		t.Errorf("First WriteHeader status = %d, want %d", tracker.writtenCodes[0], http.StatusEarlyHints)
	}
	// At the time of 103 response write, Link header should be present along with outer headers
	if got := tracker.writtenHeader[0].Get("Link"); got != "</style.css>; rel=preload" {
		t.Errorf("103 response write missing 1xx header 'Link'; got %q", got)
	}
	if got := tracker.writtenHeader[0].Get("X-Outer-Middleware"); got != "present-value" {
		t.Errorf("103 response write missing outer header 'X-Outer-Middleware'; got %q", got)
	}

	// Final WriteHeader should be 200 OK
	lastIdx := len(tracker.writtenCodes) - 1
	if tracker.writtenCodes[lastIdx] != http.StatusOK {
		t.Errorf("Final WriteHeader status = %d, want %d", tracker.writtenCodes[lastIdx], http.StatusOK)
	}
	if got := tracker.writtenHeader[lastIdx].Get("Link"); got != "" {
		t.Errorf("Final WriteHeader contained 1xx header 'Link'; got %q", got)
	}
	if got := tracker.writtenHeader[lastIdx].Get("X-Outer-Middleware"); got != "present-value" {
		t.Errorf("Final WriteHeader missing outer header 'X-Outer-Middleware'; got %q", got)
	}
}

func TestMultiple1xxPreservesDownstreamHeaders(t *testing.T) {
	// Setup backend server that emits multiple informational responses (102 and 103)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Progress", "50%")
		w.WriteHeader(http.StatusProcessing) // 102
		w.Header().Del("X-Progress")

		w.Header().Set("Link", "</script.js>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints) // 103
		w.Header().Del("Link")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	upstream := &Upstream{Host: new(Host), Dial: backend.Listener.Addr().String()}
	handler := minimalHandler(0, upstream)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	tracker := newTrackingResponseWriter(rec)

	tracker.Header().Set("X-Outer-Middleware", "outer-val")
	tracker.Header().Set("Access-Control-Allow-Origin", "*")

	err := handler.ServeHTTP(tracker, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Outer middleware headers must remain in final response
	if got := tracker.Header().Get("X-Outer-Middleware"); got != "outer-val" {
		t.Errorf("Final response missing X-Outer-Middleware; got %q", got)
	}
	if got := tracker.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Final response missing Access-Control-Allow-Origin; got %q", got)
	}

	// 1xx headers must be cleared from final response
	if got := tracker.Header().Get("X-Progress"); got != "" {
		t.Errorf("Final response contained 1xx header 'X-Progress'; got %q", got)
	}
	if got := tracker.Header().Get("Link"); got != "" {
		t.Errorf("Final response contained 1xx header 'Link'; got %q", got)
	}

	// Check final status and headers
	if got := tracker.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Final response missing Content-Type; got %q", got)
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if len(tracker.writtenCodes) < 3 {
		t.Fatalf("Expected at least 3 WriteHeader calls, got %d: %v", len(tracker.writtenCodes), tracker.writtenCodes)
	}

	// 102 Processing check
	if tracker.writtenCodes[0] != http.StatusProcessing {
		t.Errorf("First WriteHeader status = %d, want %d", tracker.writtenCodes[0], http.StatusProcessing)
	}
	if got := tracker.writtenHeader[0].Get("X-Progress"); got != "50%" {
		t.Errorf("102 response missing 'X-Progress'; got %q", got)
	}
	if got := tracker.writtenHeader[0].Get("X-Outer-Middleware"); got != "outer-val" {
		t.Errorf("102 response missing outer header 'X-Outer-Middleware'; got %q", got)
	}

	// 103 Early Hints check
	if tracker.writtenCodes[1] != http.StatusEarlyHints {
		t.Errorf("Second WriteHeader status = %d, want %d", tracker.writtenCodes[1], http.StatusEarlyHints)
	}
	if got := tracker.writtenHeader[1].Get("Link"); got != "</script.js>; rel=preload" {
		t.Errorf("103 response missing 'Link'; got %q", got)
	}
	if got := tracker.writtenHeader[1].Get("X-Progress"); got != "" {
		t.Errorf("103 response leaked previous 1xx header 'X-Progress'; got %q", got)
	}
	if got := tracker.writtenHeader[1].Get("X-Outer-Middleware"); got != "outer-val" {
		t.Errorf("103 response missing outer header 'X-Outer-Middleware'; got %q", got)
	}
}
