package caddytls

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type lockDelayStorage struct {
	certmagic.Storage
	lockCalled  chan struct{}
	lockBlock   chan struct{}
	shouldBlock atomic.Bool
}

func (s *lockDelayStorage) Lock(ctx context.Context, key string) error {
	if s.shouldBlock.Load() {
		if s.lockCalled != nil {
			select {
			case s.lockCalled <- struct{}{}:
			default:
			}
		}
		if s.lockBlock != nil {
			<-s.lockBlock
		}
	}
	return s.Storage.Lock(ctx, key)
}

var globalMockStorage certmagic.Storage

type testSlowStorageModule struct{}

func (testSlowStorageModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.test_slow",
		New: func() caddy.Module { return new(testSlowStorageModule) },
	}
}

func (testSlowStorageModule) CertMagicStorage() (certmagic.Storage, error) {
	return globalMockStorage, nil
}

func init() {
	caddy.RegisterModule(testSlowStorageModule{})
}

func TestECHRotationLockScope(t *testing.T) {
	tempDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tempDir}

	lockCalled := make(chan struct{}, 1)
	lockBlock := make(chan struct{})

	mockStorage := &lockDelayStorage{
		Storage:    fsStorage,
		lockCalled: lockCalled,
		lockBlock:  lockBlock,
	}

	globalMockStorage = mockStorage
	defer func() { globalMockStorage = nil }()

	cfg := caddy.Config{
		StorageRaw: json.RawMessage(`{"module": "test_slow"}`),
	}
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	logger := zap.NewNop()

	// Provision ECH first (shouldBlock is false)
	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outerNames from Provision")
	}

	// Age the key in memory and storage so rotation is needed
	ech.configsMu.Lock()
	for publicName, cfgs := range ech.configs {
		for i, cfg := range cfgs {
			ech.configs[publicName][i].meta.Created = time.Now().Add(-31 * 24 * time.Hour)
			metaBytes, err := json.Marshal(ech.configs[publicName][i].meta)
			if err != nil {
				t.Fatalf("failed to marshal meta: %v", err)
			}
			if err := fsStorage.Store(ctx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
				t.Fatalf("failed to store aged meta: %v", err)
			}
		}
	}
	ech.configsMu.Unlock()

	// Verify rotation is needed
	if !ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90) {
		t.Fatalf("expected rotationNeeded to return true")
	}

	// Enable blocking on storage lock for background rotation test
	mockStorage.shouldBlock.Store(true)

	// Start rotateECHKeys in background (simulating background rotation worker)
	rotateDone := make(chan error, 1)
	go func() {
		rotateDone <- ech.rotateECHKeys(ctx, logger, false)
	}()

	// Wait until rotateECHKeys attempts to acquire storage lock
	select {
	case <-lockCalled:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for storage lock attempt")
	}

	// While storage lock is blocked in rotateECHKeys, a client TLS handshake calls GetEncryptedClientHelloKeys / acquires RLock
	// It must acquire configsMu.RLock() WITHOUT BLOCKING!
	rlockAcquired := make(chan struct{})
	go func() {
		ech.configsMu.RLock()
		_ = ech.stdlibReady
		ech.configsMu.RUnlock()
		close(rlockAcquired)
	}()

	select {
	case <-rlockAcquired:
		// Success! RLock was acquired instantly while storage lock was blocked in rotateECHKeys.
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("GetEncryptedClientHelloKeys / RLock blocked while storage lock was waiting in rotateECHKeys")
	}

	// Unblock storage lock and wait for rotateECHKeys to finish
	close(lockBlock)

	select {
	case err := <-rotateDone:
		if err != nil {
			t.Fatalf("rotateECHKeys returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for rotateECHKeys to finish")
	}

	// Verify key was rotated
	ech.configsMu.RLock()
	cfgs := ech.configs["example.com"]
	if len(cfgs) < 2 {
		t.Errorf("expected rotated key to be added, got %d keys", len(cfgs))
	}
	ech.configsMu.RUnlock()
}

func TestECHRotationDeletionLockScope(t *testing.T) {
	tempDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tempDir}

	mockStorage := &lockDelayStorage{
		Storage: fsStorage,
	}

	globalMockStorage = mockStorage
	defer func() { globalMockStorage = nil }()

	cfg := caddy.Config{
		StorageRaw: json.RawMessage(`{"module": "test_slow"}`),
	}
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	logger := zap.NewNop()

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Age key beyond deleteAfter (91 days) and set Replaced to non-zero
	ech.configsMu.Lock()
	for publicName, cfgs := range ech.configs {
		for i, cfg := range cfgs {
			ech.configs[publicName][i].meta.Created = time.Now().Add(-91 * 24 * time.Hour)
			ech.configs[publicName][i].meta.Replaced = time.Now().Add(-60 * 24 * time.Hour)
			metaBytes, err := json.Marshal(ech.configs[publicName][i].meta)
			if err != nil {
				t.Fatalf("failed to marshal meta: %v", err)
			}
			if err := fsStorage.Store(ctx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
				t.Fatalf("failed to store aged meta: %v", err)
			}
		}
	}
	ech.configsMu.Unlock()

	if !ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90) {
		t.Fatalf("expected rotationNeeded to return true for expired key")
	}

	if err := ech.rotateECHKeys(ctx, logger, false); err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	ech.configsMu.RLock()
	cfgs := ech.configs["example.com"]
	if len(cfgs) != 0 {
		t.Errorf("expected expired key to be deleted, got %d keys", len(cfgs))
	}
	ech.configsMu.RUnlock()
}
