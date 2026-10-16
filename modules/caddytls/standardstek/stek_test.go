package standardstek

import (
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type failOnceReader struct {
	failed uint32
	real   io.Reader
}

func (f *failOnceReader) Read(p []byte) (n int, err error) {
	if atomic.CompareAndSwapUint32(&f.failed, 0, 1) {
		return 0, errors.New("simulated transient entropy failure")
	}
	return f.real.Read(p)
}

func TestStandardSTEKRotationRecovery(t *testing.T) {
	oldReader := rand.Reader
	defer func() { rand.Reader = oldReader }()

	config := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := new(standardSTEKProvider)
	initKeys, err := provider.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected non-empty init keys")
	}

	// Inject transient entropy failure after initialization
	failing := &failOnceReader{real: oldReader}
	rand.Reader = failing

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := provider.Next(doneChan)

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("expected non-empty rotated keys")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for key rotation recovery after transient entropy failure")
	}
}
