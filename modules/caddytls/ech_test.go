package caddytls

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type slowStorage struct {
	certmagic.Storage
	inStorageOp      chan struct{}
	releaseStorageOp chan struct{}
	once             sync.Once
}

func (s *slowStorage) Lock(ctx context.Context, name string) error {
	s.once.Do(func() {
		if s.inStorageOp != nil {
			s.inStorageOp <- struct{}{}
		}
		if s.releaseStorageOp != nil {
			<-s.releaseStorageOp
		}
	})
	return s.Storage.Lock(ctx, name)
}

func TestECHKeyRotationLockDecoupling(t *testing.T) {
	tmpDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tmpDir}

	inStorageOp := make(chan struct{})
	releaseStorageOp := make(chan struct{})

	slow := &slowStorage{
		Storage:          fsStorage,
		inStorageOp:      inStorageOp,
		releaseStorageOp: releaseStorageOp,
	}

	origDefault := caddy.DefaultStorage
	caddy.DefaultStorage = slow
	t.Cleanup(func() {
		caddy.DefaultStorage = origDefault
	})

	cfg := &caddy.Config{}
	caddyCtx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("failed to create caddy context: %v", err)
	}

	publicName := "example.com"
	echCfg, err := generateAndStoreECHConfig(caddyCtx, publicName)
	if err != nil {
		t.Fatalf("failed to generate ECH config: %v", err)
	}

	// Set metadata created time to 31 days ago so rotation is needed
	echCfg.meta.Created = time.Now().Add(-31 * 24 * time.Hour)
	metaBytes, err := json.Marshal(echCfg.meta)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}
	if err := fsStorage.Store(caddyCtx, echMetaKey(echCfg.ConfigID), metaBytes); err != nil {
		t.Fatalf("failed to store metadata: %v", err)
	}

	logger := zap.NewNop()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			publicName: {echCfg},
		},
	}
	ech.updateKeyList()

	// Verify rotationNeeded is true initially
	if !ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90) {
		t.Fatalf("expected rotationNeeded to be true for 31-day-old config")
	}

	// Launch rotateECHKeys with slow storage in a background goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- ech.rotateECHKeys(caddyCtx, logger, false)
	}()

	// Wait until rotateECHKeys reaches slow storage.Lock
	select {
	case <-inStorageOp:
		// rotateECHKeys is currently stalled waiting on storage lock!
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rotateECHKeys to enter storage operation")
	}

	// Concurrently attempt to acquire RLock (simulating GetEncryptedClientHelloKeys)
	rlockAcquired := make(chan struct{})
	go func() {
		ech.configsMu.RLock()
		defer ech.configsMu.RUnlock()
		close(rlockAcquired)
	}()

	// RLock should succeed immediately while storage operation is stalled
	select {
	case <-rlockAcquired:
		// Success: configsMu was NOT held during network storage lock acquisition!
	case <-time.After(500 * time.Millisecond):
		releaseStorageOp <- struct{}{}
		t.Fatal("configsMu.RLock() blocked during background ECH key rotation storage operation")
	}

	// Release the storage operation to let rotateECHKeys finish
	releaseStorageOp <- struct{}{}

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("rotateECHKeys failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rotateECHKeys timed out completing")
	}

	// Verify updated key list is non-empty and contains new rotated config
	ech.configsMu.RLock()
	defer ech.configsMu.RUnlock()
	if len(ech.stdlibReady) < 2 {
		t.Fatalf("expected at least 2 stdlibReady keys after rotation, got %d", len(ech.stdlibReady))
	}
}
