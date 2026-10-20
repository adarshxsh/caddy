package caddytls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type slowStorage struct {
	certmagic.Storage
	lockCalled atomic.Bool
	delay      time.Duration
}

func (s *slowStorage) Lock(ctx context.Context, key string) error {
	s.lockCalled.Store(true)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.Storage.Lock(ctx, key)
}

func (s *slowStorage) Store(ctx context.Context, key string, value []byte) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.Storage.Store(ctx, key, value)
}

func (s *slowStorage) Delete(ctx context.Context, key string) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.Storage.Delete(ctx, key)
}

func TestECHRotationNotNeeded(t *testing.T) {
	tmpDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tmpDir}
	slowStore := &slowStorage{Storage: fsStorage, delay: 100 * time.Millisecond}

	oldDefaultStorage := caddy.DefaultStorage
	oldCertMagicStorage := certmagic.Default.Storage
	caddy.DefaultStorage = fsStorage
	certmagic.Default.Storage = slowStore
	defer func() {
		caddy.DefaultStorage = oldDefaultStorage
		certmagic.Default.Storage = oldCertMagicStorage
	}()

	cfg := &caddy.Config{}

	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Reset lockCalled flag
	slowStore.lockCalled.Store(false)

	logger := zap.NewNop()
	err = ech.rotateECHKeys(ctx, logger, false)
	if err != nil {
		t.Fatalf("rotateECHKeys returned error: %v", err)
	}

	if slowStore.lockCalled.Load() {
		t.Fatalf("rotateECHKeys acquired cluster storage lock even though rotation was not needed")
	}
}

func TestECHRotationLockingAndConcurrentHandshakes(t *testing.T) {
	tmpDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tmpDir}
	slowStore := &slowStorage{Storage: fsStorage, delay: 50 * time.Millisecond}

	oldDefaultStorage := caddy.DefaultStorage
	oldCertMagicStorage := certmagic.Default.Storage
	caddy.DefaultStorage = fsStorage
	certmagic.Default.Storage = slowStore
	defer func() {
		caddy.DefaultStorage = oldDefaultStorage
		certmagic.Default.Storage = oldCertMagicStorage
	}()

	cfg := &caddy.Config{}

	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Age the ECH config metadata in storage to force rotation (31 days old)
	ech.configsMu.RLock()
	cfgs := ech.configs["public.example.com"]
	if len(cfgs) == 0 {
		t.Fatalf("no ECH config found")
	}
	oldConfigID := cfgs[0].ConfigID
	ech.configsMu.RUnlock()

	metaKey := echMetaKey(oldConfigID)
	metaBytes, err := slowStore.Load(ctx, metaKey)
	if err != nil {
		keys, listErr := slowStore.List(ctx, echConfigsKey, true)
		t.Fatalf("failed to load meta.json for key %s: %v (existing keys: %v, listErr: %v)", metaKey, err, keys, listErr)
	}

	var meta echConfigMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("failed to unmarshal meta: %v", err)
	}

	meta.Created = time.Now().Add(-31 * 24 * time.Hour)
	updatedMetaBytes, _ := json.Marshal(meta)
	if err := slowStore.Store(ctx, metaKey, updatedMetaBytes); err != nil {
		t.Fatalf("failed to update meta.json: %v", err)
	}

	// Reload updated metadata into memory
	_, err = ech.setConfigsFromStorage(ctx, zap.NewNop())
	if err != nil {
		t.Fatalf("setConfigsFromStorage failed: %v", err)
	}

	// Verify rotation is needed
	ech.configsMu.RLock()
	needed := ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90)
	ech.configsMu.RUnlock()
	if !needed {
		t.Fatalf("expected rotationNeeded to return true for aged key")
	}

	// Run rotation in background and perform concurrent handshake key reads
	var maxHandshakeDelay time.Duration
	var delayMu sync.Mutex

	stopHandshakes := make(chan struct{})
	var wg sync.WaitGroup

	// Start 10 concurrent handshake readers simulating active TLS handshakes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopHandshakes:
					return
				default:
					start := time.Now()
					ech.configsMu.RLock()
					_ = append([]tls.EncryptedClientHelloKey(nil), ech.stdlibReady...)
					ech.configsMu.RUnlock()
					dur := time.Since(start)

					delayMu.Lock()
					if dur > maxHandshakeDelay {
						maxHandshakeDelay = dur
					}
					delayMu.Unlock()

					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	logger := zap.NewNop()
	rotateErr := ech.rotateECHKeys(ctx, logger, false)

	close(stopHandshakes)
	wg.Wait()

	if rotateErr != nil {
		t.Fatalf("rotateECHKeys failed: %v", rotateErr)
	}

	// Assert handshake read delay was under 10ms (and nowhere near the 50ms+ storage delays)
	if maxHandshakeDelay > 10*time.Millisecond {
		t.Fatalf("TLS handshake key retrieval stalled during key rotation: max delay = %v", maxHandshakeDelay)
	}

	// Assert that new key was generated and added to stdlibReady
	ech.configsMu.RLock()
	finalKeys := ech.stdlibReady
	ech.configsMu.RUnlock()

	if len(finalKeys) < 2 {
		t.Fatalf("expected at least 2 stdlibReady keys after rotation, got %d", len(finalKeys))
	}
}

func TestECHRotationWriteLockDuration(t *testing.T) {
	tmpDir := t.TempDir()
	fsStorage := &certmagic.FileStorage{Path: tmpDir}
	slowStore := &slowStorage{Storage: fsStorage, delay: 50 * time.Millisecond}

	oldDefaultStorage := caddy.DefaultStorage
	oldCertMagicStorage := certmagic.Default.Storage
	caddy.DefaultStorage = fsStorage
	certmagic.Default.Storage = slowStore
	defer func() {
		caddy.DefaultStorage = oldDefaultStorage
		certmagic.Default.Storage = oldCertMagicStorage
	}()

	cfg := &caddy.Config{}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ech.configsMu.RLock()
	cfgs := ech.configs["public.example.com"]
	oldConfigID := cfgs[0].ConfigID
	ech.configsMu.RUnlock()

	metaKey := echMetaKey(oldConfigID)
	metaBytes, err := slowStore.Load(ctx, metaKey)
	if err != nil {
		t.Fatalf("failed to load metaKey: %v", err)
	}

	var meta echConfigMeta
	_ = json.Unmarshal(metaBytes, &meta)
	meta.Created = time.Now().Add(-31 * 24 * time.Hour)
	updatedMetaBytes, _ := json.Marshal(meta)
	_ = slowStore.Store(ctx, metaKey, updatedMetaBytes)

	_, _ = ech.setConfigsFromStorage(ctx, zap.NewNop())

	var maxLockBlockedDuration time.Duration
	var lockMu sync.Mutex
	stopPoll := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(100 * time.Microsecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopPoll:
				return
			case <-ticker.C:
				start := time.Now()
				ech.configsMu.RLock()
				_ = ech.stdlibReady
				ech.configsMu.RUnlock()
				dur := time.Since(start)

				lockMu.Lock()
				if dur > maxLockBlockedDuration {
					maxLockBlockedDuration = dur
				}
				lockMu.Unlock()
			}
		}
	}()

	logger := zap.NewNop()
	err = ech.rotateECHKeys(ctx, logger, false)
	close(stopPoll)
	wg.Wait()

	if err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	if maxLockBlockedDuration > 1*time.Millisecond {
		t.Fatalf("write lock duration during key state update exceeded 1ms: %v", maxLockBlockedDuration)
	}
}
