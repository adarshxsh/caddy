package caddytls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"path"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func createTestECH(t *testing.T) (*ECH, caddy.Context, string) {
	t.Helper()
	tmpDir := t.TempDir()
	origStorage := caddy.DefaultStorage
	caddy.DefaultStorage = &certmagic.FileStorage{Path: tmpDir}
	t.Cleanup(func() {
		caddy.DefaultStorage = origStorage
	})

	ctx, cancel := caddy.NewContext(caddy.Context{
		Context: context.Background(),
	})
	t.Cleanup(cancel)

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}

	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outerNames from Provision, got empty")
	}

	return ech, ctx, tmpDir
}

// TestLockFreeGetEncryptedClientHelloKeys verifies that GetEncryptedClientHelloKeys
// completes immediately without acquiring configsMu read locks, even when configsMu.Lock is held.
func TestLockFreeGetEncryptedClientHelloKeys(t *testing.T) {
	ech, _, _ := createTestECH(t)

	// Ensure keys are loaded initially
	keys, err := ech.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetEncryptedClientHelloKeys returned error: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("expected non-empty ECH keys")
	}

	// Acquire write lock on configsMu to simulate write lock contention
	ech.configsMu.Lock()

	done := make(chan struct{})
	var loadedKeys []tls.EncryptedClientHelloKey
	var loadErr error

	go func() {
		defer close(done)
		loadedKeys, loadErr = ech.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{})
	}()

	select {
	case <-done:
		// Success: GetEncryptedClientHelloKeys finished without waiting for configsMu
		if loadErr != nil {
			t.Fatalf("GetEncryptedClientHelloKeys failed: %v", loadErr)
		}
		if len(loadedKeys) != len(keys) {
			t.Fatalf("expected %d keys, got %d", len(keys), len(loadedKeys))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("GetEncryptedClientHelloKeys blocked waiting for configsMu write lock!")
	}

	ech.configsMu.Unlock()
}

// TestDecoupledRotateECHKeys verifies that rotateECHKeys performs storage locking and storage operations
// out-of-band and updates atomic memory pointers.
func TestDecoupledRotateECHKeys(t *testing.T) {
	ech, ctx, _ := createTestECH(t)
	logger := ctx.Logger().Named("ech")

	// Get initial keys
	initialKeys, err := ech.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{})
	if err != nil || len(initialKeys) == 0 {
		t.Fatalf("failed to get initial keys: %v", err)
	}

	// Age the config in memory and storage so rotation is needed (>= 30 days old)
	ech.configsMu.Lock()
	for publicName, cfgs := range ech.configs {
		for i := range cfgs {
			ech.configs[publicName][i].meta.Created = time.Now().Add(-31 * 24 * time.Hour)
			// Persist updated metadata in storage
			metaBytes, _ := json.Marshal(ech.configs[publicName][i].meta)
			_ = ctx.Storage().Store(ctx, echMetaKey(ech.configs[publicName][i].ConfigID), metaBytes)
		}
	}
	ech.configsMu.Unlock()

	// Perform rotation without holding configsMu lock
	err = ech.rotateECHKeys(ctx, logger, false)
	if err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	// Verify atomic pointer updated with new rotated keys
	rotatedKeys, err := ech.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetEncryptedClientHelloKeys failed after rotation: %v", err)
	}

	if len(rotatedKeys) <= len(initialKeys) {
		t.Fatalf("expected additional rotated key, initial len: %d, new len: %d", len(initialKeys), len(rotatedKeys))
	}
}

// TestExpiredKeyCleanup verifies that keys older than 90 days are cleaned up from storage and memory pointers.
func TestExpiredKeyCleanup(t *testing.T) {
	ech, ctx, _ := createTestECH(t)
	logger := ctx.Logger().Named("ech")

	// Age and mark config as replaced and expired (> 90 days)
	ech.configsMu.Lock()
	var expiredID uint8
	for publicName, cfgs := range ech.configs {
		for i := range cfgs {
			ech.configs[publicName][i].meta.Created = time.Now().Add(-95 * 24 * time.Hour)
			ech.configs[publicName][i].meta.Replaced = time.Now().Add(-60 * 24 * time.Hour)
			expiredID = ech.configs[publicName][i].ConfigID
			metaBytes, _ := json.Marshal(ech.configs[publicName][i].meta)
			_ = ctx.Storage().Store(ctx, echMetaKey(expiredID), metaBytes)
		}
	}
	ech.configsMu.Unlock()

	// Rotate keys (which should delete the expired key)
	err := ech.rotateECHKeys(ctx, logger, false)
	if err != nil {
		t.Fatalf("rotateECHKeys failed during expiration cleanup: %v", err)
	}

	// Verify the key file was deleted from storage
	cfgIDKey := path.Join(echConfigsKey, strconv.Itoa(int(expiredID)))
	if ctx.Storage().Exists(ctx, cfgIDKey) {
		t.Fatalf("expected expired key %s to be deleted from storage", cfgIDKey)
	}
}

// BenchmarkConcurrentGetEncryptedClientHelloKeys measures lock-free performance under concurrent readers
// while background storage operations run.
func BenchmarkConcurrentGetEncryptedClientHelloKeys(b *testing.B) {
	tmpDir := b.TempDir()
	origStorage := caddy.DefaultStorage
	caddy.DefaultStorage = &certmagic.FileStorage{Path: tmpDir}
	defer func() {
		caddy.DefaultStorage = origStorage
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{
		Context: context.Background(),
	})
	defer cancel()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}
	_, err := ech.Provision(ctx)
	if err != nil {
		b.Fatalf("Provision failed: %v", err)
	}

	// Simulate background storage lock hold in a background goroutine
	var stopBG atomic.Bool
	go func() {
		for !stopBG.Load() {
			ech.configsMu.Lock()
			time.Sleep(1 * time.Millisecond) // simulate lock hold
			ech.configsMu.Unlock()
			time.Sleep(1 * time.Millisecond)
		}
	}()
	defer stopBG.Store(true)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		chi := &tls.ClientHelloInfo{}
		for pb.Next() {
			keys, err := ech.GetEncryptedClientHelloKeys(chi)
			if err != nil || len(keys) == 0 {
				b.Fatalf("failed to fetch ECH keys: %v", err)
			}
		}
	})
}
