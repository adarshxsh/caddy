package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
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

	buf, bufPtr := copier.buffer()
	if bufPtr != nil {
		defer streamingBufPool.Put(bufPtr)
	}
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
	buf, bufPtr := copier.buffer()
	if bufPtr != nil {
		defer streamingBufPool.Put(bufPtr)
	}
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
}

func TestSwitchProtocolCopierBufferPoolReuse(t *testing.T) {
	copier := switchProtocolCopier{}

	// Retrieve buffer from pool
	buf1, bufPtr1 := copier.buffer()
	if got := len(buf1); got != defaultBufferSize {
		t.Fatalf("buf1 len = %d, want %d", got, defaultBufferSize)
	}
	if bufPtr1 == nil {
		t.Fatal("expected non-nil bufPtr for default buffer size")
	}

	// Release buffer back to pool
	streamingBufPool.Put(bufPtr1)

	// Retrieve buffer again; should be valid and from pool
	buf2, bufPtr2 := copier.buffer()
	if got := len(buf2); got != defaultBufferSize {
		t.Fatalf("buf2 len = %d, want %d", got, defaultBufferSize)
	}
	if bufPtr2 == nil {
		t.Fatal("expected non-nil bufPtr for default buffer size")
	}
	streamingBufPool.Put(bufPtr2)

	// Test full copyToBackend and copyFromBackend workflow with pooled buffer
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	var toBackendDst, fromBackendDst bytes.Buffer

	spc := switchProtocolCopier{
		user:    nopReadWriteCloser{Reader: strings.NewReader("user-to-backend"), Writer: &fromBackendDst},
		backend: nopReadWriteCloser{Reader: strings.NewReader("backend-to-user"), Writer: &toBackendDst},
		wg:      &wg,
	}

	wg.Add(2)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	wg.Wait()

	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatalf("unexpected copier error: %v", err)
		}
	}

	if got := toBackendDst.String(); got != "user-to-backend" {
		t.Fatalf("copyToBackend output = %q, want %q", got, "user-to-backend")
	}
	if got := fromBackendDst.String(); got != "backend-to-user" {
		t.Fatalf("copyFromBackend output = %q, want %q", got, "backend-to-user")
	}
}

func TestSwitchProtocolCopierCustomBufferSizeFallback(t *testing.T) {
	customSizes := []int{1024, 8192, 65536}

	for _, size := range customSizes {
		copier := switchProtocolCopier{bufferSize: size}
		buf, bufPtr := copier.buffer()

		if got := len(buf); got != size {
			t.Fatalf("custom buffer len = %d, want %d", got, size)
		}
		if bufPtr != nil {
			t.Fatalf("expected nil bufPtr for custom buffer size %d, got non-nil", size)
		}
	}
}

func TestSwitchProtocolCopierAllocations(t *testing.T) {
	copier := switchProtocolCopier{}

	// Warm up sync.Pool
	buf, bufPtr := copier.buffer()
	if bufPtr != nil {
		streamingBufPool.Put(bufPtr)
	}
	_ = buf

	allocs := testing.AllocsPerRun(100, func() {
		b, bp := copier.buffer()
		if bp != nil {
			streamingBufPool.Put(bp)
		}
		_ = b
	})

	if allocs > 0 {
		t.Fatalf("expected 0 allocations per buffer retrieval from pool, got %f", allocs)
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }
