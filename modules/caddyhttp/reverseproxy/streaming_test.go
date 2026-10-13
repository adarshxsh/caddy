package reverseproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHandlerCopyResponse(t *testing.T) {
	h := Handler{}
	testdata := []string{
		"",
		strings.Repeat("a", defaultBufferSize),
		strings.Repeat("123456789 123456789 123456789 12", 3000),
	}

	dst := bytes.NewBuffer(nil)
	recorder := httptest.NewRecorder()
	recorder.Body = dst

	for _, d := range testdata {
		src := bytes.NewBuffer([]byte(d))
		dst.Reset()
		err := h.copyResponse(recorder, src, 0, caddy.Log())
		if err != nil {
			t.Errorf("failed with error: %v", err)
		}
		out := dst.String()
		if out != d {
			t.Errorf("bad read: got %q", out)
		}
	}
}

func TestSwitchProtocolCopierBufferSize(t *testing.T) {
	var wg sync.WaitGroup
	var errc = make(chan error, 1)
	var dst bytes.Buffer

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 7,
	}

	buf := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "hello" {
		t.Fatalf("copied data = %q, want %q", got, "hello")
	}
}

func TestSwitchProtocolCopierDefaultBufferSize(t *testing.T) {
	copier := switchProtocolCopier{}
	buf := copier.buffer()
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
}

func TestResponseTrailers(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedBody    string
		expectedTrailer map[string]string
	}{
		{
			name: "preannounced trailers",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "At-End, X-Status")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello preannounced"))
				w.Header().Set("Trailer:At-End", "finished")
				w.Header().Set("Trailer:X-Status", "ok")
			},
			expectedBody: "hello preannounced",
			expectedTrailer: map[string]string{
				"At-End":   "finished",
				"X-Status": "ok",
			},
		},
		{
			name: "unannounced trailers",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer:Grpc-Status", "0")
				w.Header().Set("Trailer:Grpc-Message", "success")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello unannounced"))
			},
			expectedBody: "hello unannounced",
			expectedTrailer: map[string]string{
				"Grpc-Status":  "0",
				"Grpc-Message": "success",
			},
		},
		{
			name: "mixed preannounced and unannounced trailers",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "Pre-Announced")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello mixed"))
				w.Header().Set("Trailer:Pre-Announced", "val1")
				w.Header().Set("Trailer:Unannounced", "val2")
			},
			expectedBody: "hello mixed",
			expectedTrailer: map[string]string{
				"Pre-Announced": "val1",
				"Unannounced":   "val2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(tt.handler)
			defer upstream.Close()

			h := &Handler{
				logger:    zap.NewNop(),
				Transport: testTransport{&http.Transport{}},
				Upstreams: UpstreamPool{
					{Host: new(Host), Dial: upstream.Listener.Addr().String()},
				},
				LoadBalancing: &LoadBalancing{
					SelectionPolicy: &RandomSelection{},
				},
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req = prepareTestRequest(req)
			rec := httptest.NewRecorder()

			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))
			if err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			res := rec.Result()
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()

			if got := string(body); got != tt.expectedBody {
				t.Errorf("body = %q, want %q", got, tt.expectedBody)
			}

			for k, want := range tt.expectedTrailer {
				if got := res.Trailer.Get(k); got != want {
					t.Errorf("trailer %s = %q, want %q (got trailers: %v)", k, got, want, res.Trailer)
				}
			}
		})
	}

	t.Run("trailers populated on body close", func(t *testing.T) {
		trailerMap := make(http.Header)
		trailerMap["At-End"] = nil

		bodyReadCloser := &trailerBody{
			Reader: strings.NewReader("hello trailer body"),
			onClose: func() {
				trailerMap["At-End"] = []string{"final-value"}
			},
		}

		tr := &mockTransport{
			res: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Trailer:    trailerMap,
				Body:       bodyReadCloser,
			},
		}

		h := &Handler{
			logger:    zap.NewNop(),
			Transport: tr,
			Upstreams: UpstreamPool{
				{Host: new(Host), Dial: "127.0.0.1:8080"},
			},
			LoadBalancing: &LoadBalancing{
				SelectionPolicy: &RandomSelection{},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req = prepareTestRequest(req)
		rec := httptest.NewRecorder()

		err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		}))
		if err != nil {
			t.Fatalf("ServeHTTP failed: %v", err)
		}

		res := rec.Result()
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		if got, want := string(body), "hello trailer body"; got != want {
			t.Errorf("body = %q, want %q", got, want)
		}

		if got, want := res.Trailer.Get("At-End"), "final-value"; got != want {
			t.Errorf("trailer At-End = %q, want %q (got trailers: %v)", got, want, res.Trailer)
		}
	})
}

type trailerBody struct {
	io.Reader
	onClose func()
}

func (tb *trailerBody) Close() error {
	if tb.onClose != nil {
		tb.onClose()
	}
	return nil
}

type mockTransport struct {
	res *http.Response
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.res, nil
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

