package caddytls

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestECHRotationLockScope(t *testing.T) {
	tempDir := t.TempDir()
	caddy.DefaultStorage = &certmagic.FileStorage{Path: tempDir}

	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("Provisioning caddy config: %v", err)
	}
	ctx, cancel := caddy.NewContext(caddyCtx)
	defer cancel()

	logger := zap.NewNop()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if len(outerNames) != 1 || outerNames[0] != "example.com" {
		t.Fatalf("unexpected outerNames: %v", outerNames)
	}

	ech.configsMu.RLock()
	initialKeyCount := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if initialKeyCount == 0 {
		t.Fatal("expected stdlibReady to contain initial keys")
	}

	// Age the existing config so rotation is required
	ech.configsMu.Lock()
	for name := range ech.configs {
		for i := range ech.configs[name] {
			ech.configs[name][i].meta.Created = time.Now().Add(-24 * time.Hour * 31)
			metaBytes, _ := jsonMarshal(ech.configs[name][i].meta)
			_ = ctx.Storage().Store(ctx, echMetaKey(ech.configs[name][i].ConfigID), metaBytes)
		}
	}
	ech.configsMu.Unlock()

	// Verify rotationNeeded returns true
	ech.configsMu.RLock()
	needed := ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90)
	ech.configsMu.RUnlock()
	if !needed {
		t.Fatal("expected rotation to be needed")
	}

	// Start a concurrent reader simulating GetEncryptedClientHelloKeys during TLS handshake
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	readDone := make(chan struct{})

	go func() {
		defer readerWg.Done()
		for {
			select {
			case <-readDone:
				return
			default:
				ech.configsMu.RLock()
				_ = len(ech.stdlibReady)
				time.Sleep(100 * time.Microsecond)
				ech.configsMu.RUnlock()
			}
		}
	}()

	// Execute rotateECHKeys out-of-lock
	err = ech.rotateECHKeys(ctx, logger, false)
	close(readDone)
	readerWg.Wait()

	if err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	// Verify rotation added a replacement key
	ech.configsMu.RLock()
	newKeyCount := len(ech.stdlibReady)
	hasReplaced := false
	for _, cfgs := range ech.configs {
		for _, cfg := range cfgs {
			if !cfg.meta.Replaced.IsZero() {
				hasReplaced = true
			}
		}
	}
	ech.configsMu.RUnlock()

	if newKeyCount <= initialKeyCount {
		t.Fatalf("expected key count to increase after rotation, got before=%d, after=%d", initialKeyCount, newKeyCount)
	}
	if !hasReplaced {
		t.Fatal("expected old key to be marked as replaced after rotation")
	}
}

func TestECHExpirationDeletion(t *testing.T) {
	tempDir := t.TempDir()
	caddy.DefaultStorage = &certmagic.FileStorage{Path: tempDir}

	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("Provisioning caddy config: %v", err)
	}
	ctx, cancel := caddy.NewContext(caddyCtx)
	defer cancel()

	logger := zap.NewNop()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.org"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Age and mark key as replaced for > 90 days so deletion occurs
	ech.configsMu.Lock()
	for name := range ech.configs {
		for i := range ech.configs[name] {
			ech.configs[name][i].meta.Created = time.Now().Add(-24 * time.Hour * 91)
			ech.configs[name][i].meta.Replaced = time.Now().Add(-24 * time.Hour * 91)
			metaBytes, _ := jsonMarshal(ech.configs[name][i].meta)
			_ = ctx.Storage().Store(ctx, echMetaKey(ech.configs[name][i].ConfigID), metaBytes)
		}
	}
	ech.configsMu.Unlock()

	err = ech.rotateECHKeys(ctx, logger, false)
	if err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	ech.configsMu.RLock()
	for _, cfgs := range ech.configs {
		for _, cfg := range cfgs {
			if time.Since(cfg.meta.Created) >= 24*time.Hour*90 && !cfg.meta.Replaced.IsZero() {
				t.Fatalf("expired key %d was not deleted", cfg.ConfigID)
			}
		}
	}
	ech.configsMu.RUnlock()
}

// jsonMarshal is a helper wrapper for encoding json in tests
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
