package distributedstek

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type transientErrorStorage struct {
	certmagic.Storage
	failLoad uint32
}

func (s *transientErrorStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if atomic.CompareAndSwapUint32(&s.failLoad, 1, 0) {
		return nil, errors.New("simulated transient storage failure")
	}
	return s.Storage.Load(ctx, key)
}

func TestDistributedSTEKRotationRecovery(t *testing.T) {
	tempDir := t.TempDir()
	baseStorage := &certmagic.FileStorage{Path: tempDir}
	mockStorage := &transientErrorStorage{Storage: baseStorage}

	config := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &Provider{
		storage: mockStorage,
	}

	initKeys, err := provider.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected non-empty initial keys")
	}

	// Trigger transient storage failure for the next load operation
	atomic.StoreUint32(&mockStorage.failLoad, 1)

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := provider.Next(doneChan)

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("expected non-empty rotated keys")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for distributed STEK rotation recovery after transient storage failure")
	}
}
