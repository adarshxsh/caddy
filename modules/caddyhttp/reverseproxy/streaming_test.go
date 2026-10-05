package reverseproxy

import (
	"bytes"
	"context"
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

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

func TestReverseProxyPreannouncedTrailers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Test-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello trailer"))
		w.Header().Set(http.TrailerPrefix+"X-Test-Trailer", "trailer-value")
	}))
	defer backend.Close()

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	transport := new(HTTPTransport)
	if err := transport.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision transport failed: %v", err)
	}

	h := &Handler{
		logger:    zap.NewNop(),
		Transport: transport,
		Upstreams: UpstreamPool{
			{
				Dial: backend.Listener.Addr().String(),
				Host: new(Host),
			},
		},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RandomSelection{},
		},
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := caddyhttp.PrepareRequest(r, caddy.NewReplacer(), nil, &caddyhttp.Server{})
		_ = h.ServeHTTP(w, req, nil)
	}))
	defer proxyServer.Close()

	res, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(body) != "hello trailer" {
		t.Errorf("got body %q, want %q", string(body), "hello trailer")
	}

	if got := res.Trailer.Get("X-Test-Trailer"); got != "trailer-value" {
		t.Errorf("Trailer X-Test-Trailer = %q, want %q; res.Trailer = %#v", got, "trailer-value", res.Trailer)
	}
}
