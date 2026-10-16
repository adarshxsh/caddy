package caddytls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type slowTestStorage struct {
	certmagic.Storage
	lockDelay time.Duration
	listDelay time.Duration
}

func (s *slowTestStorage) Lock(ctx context.Context, name string) error {
	if s.lockDelay > 0 {
		time.Sleep(s.lockDelay)
	}
	return s.Storage.Lock(ctx, name)
}

func (s *slowTestStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if s.listDelay > 0 {
		time.Sleep(s.listDelay)
	}
	return s.Storage.List(ctx, prefix, recursive)
}

func TestECHRotationLockDecoupling(t *testing.T) {
	cfg := &caddy.Config{}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	slowStore := &slowTestStorage{
		Storage:   ctx.Storage(),
		lockDelay: 150 * time.Millisecond,
		listDelay: 150 * time.Millisecond,
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	logger := zap.NewNop()

	// Initial provision
	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outerNames, got empty")
	}

	ech.configsMu.RLock()
	initialKeyCount := len(ech.stdlibReady)
	if initialKeyCount == 0 {
		ech.configsMu.RUnlock()
		t.Fatalf("expected stdlibReady keys after Provision")
	}
	ech.configsMu.RUnlock()

	// Directly modify ech.configs in memory to age the metadata for testing
	ech.configsMu.Lock()
	for pName := range ech.configs {
		for i := range ech.configs[pName] {
			ech.configs[pName][i].meta.Created = time.Now().Add(-31 * 24 * time.Hour)
			metaBytes, _ := json.Marshal(ech.configs[pName][i].meta)
			_ = ctx.Storage().Store(ctx, echMetaKey(ech.configs[pName][i].ConfigID), metaBytes)
		}
	}
	ech.configsMu.Unlock()

	// Verify rotationNeeded is true
	ech.configsMu.RLock()
	needed := ech.rotationNeeded(24*time.Hour*30, 24*time.Hour*90)
	ech.configsMu.RUnlock()
	if !needed {
		t.Fatalf("expected rotationNeeded to be true after aging key metadata")
	}

	var wg sync.WaitGroup
	wg.Add(1)

	rotationStarted := make(chan struct{})
	rotationDone := make(chan error, 1)

	go func() {
		defer wg.Done()
		close(rotationStarted)
		err := ech.rotateECHKeysWithStorage(ctx, slowStore, logger, false)
		rotationDone <- err
	}()

	<-rotationStarted

	// Concurrently attempt to read ECH keys using RLock (simulating TLS handshakes)
	// This must NOT block behind slowStore (150ms lockDelay + 150ms listDelay = ~300ms)
	handshakeDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		ech.configsMu.RLock()
		_ = ech.stdlibReady
		ech.configsMu.RUnlock()
		handshakeDone <- time.Since(start)
	}()

	select {
	case readDuration := <-handshakeDone:
		if readDuration > 50*time.Millisecond {
			t.Fatalf("TLS handshake key retrieval blocked for %v (expected < 50ms)", readDuration)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("TLS handshake key retrieval timed out waiting for RLock")
	}

	wg.Wait()
	if err := <-rotationDone; err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	// Verify that stdlibReady was updated after rotation
	ech.configsMu.RLock()
	newKeyCount := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if newKeyCount <= initialKeyCount {
		t.Fatalf("expected new key to be added after rotation: initial=%d, new=%d", initialKeyCount, newKeyCount)
	}
}

func (ech *ECH) rotateECHKeysWithStorage(ctx caddy.Context, customStorage certmagic.Storage, logger *zap.Logger, storageSynced bool) error {
	const (
		rotationInterval = 24 * time.Hour * 30
		deleteAfter      = 24 * time.Hour * 90
	)

	ech.configsMu.RLock()
	needed := ech.rotationNeeded(rotationInterval, deleteAfter)
	ech.configsMu.RUnlock()

	if !needed {
		return nil
	}

	if !storageSynced {
		if err := customStorage.Lock(ctx, echStorageLockName); err != nil {
			return err
		}
		defer func() {
			if err := customStorage.Unlock(ctx, echStorageLockName); err != nil {
				logger.Error("unable to unlock ECH rotation in storage", zap.Error(err))
			}
		}()
	}

	_, workingConfigs, err := loadConfigsFromCustomStorage(ctx, customStorage, logger)
	if err != nil {
		return err
	}

	for publicName := range workingConfigs {
		for i := 0; i < len(workingConfigs[publicName]); i++ {
			cfg := workingConfigs[publicName][i]
			if time.Since(cfg.meta.Created) >= rotationInterval && cfg.meta.Replaced.IsZero() {
				newCfg, err := generateAndStoreECHConfig(ctx, publicName)
				if err != nil {
					return err
				}

				workingConfigs[publicName][i].meta.Replaced = time.Now()

				metaBytes, err := json.Marshal(workingConfigs[publicName][i].meta)
				if err != nil {
					return err
				}
				if err := customStorage.Store(ctx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
					return err
				}

				workingConfigs[publicName] = append(workingConfigs[publicName], newCfg)
			}
		}
	}

	ech.configsMu.Lock()
	ech.configs = workingConfigs
	ech.updateKeyList()
	ech.configsMu.Unlock()

	return nil
}

func loadConfigsFromCustomStorage(ctx caddy.Context, storage certmagic.Storage, logger *zap.Logger) ([]string, map[string][]echConfig, error) {
	configs := make(map[string][]echConfig)
	var outerNames []string

	cfgKeys, err := storage.List(ctx, echConfigsKey, false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	for _, cfgKey := range cfgKeys {
		cfg, err := loadECHConfig(ctx, path.Base(cfgKey))
		if err != nil {
			return nil, nil, err
		}
		if cfg.configBin == nil || cfg.privKeyBin == nil {
			continue
		}
		if _, seen := configs[cfg.RawPublicName]; !seen {
			outerNames = append(outerNames, cfg.RawPublicName)
		}
		configs[cfg.RawPublicName] = append(configs[cfg.RawPublicName], cfg)
	}

	return outerNames, configs, nil
}

func TestECHRotationNotNeeded(t *testing.T) {
	cfg := &caddy.Config{}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "fresh.example.com"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	logger := zap.NewNop()

	err = ech.rotateECHKeys(ctx, logger, false)
	if err != nil {
		t.Fatalf("rotateECHKeys unexpectedly failed: %v", err)
	}
}

func TestGetEncryptedClientHelloKeysThreadSafety(t *testing.T) {
	tlsApp := &TLS{
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			stdlibReady: []tls.EncryptedClientHelloKey{
				{Config: []byte("test-config"), PrivateKey: []byte("test-key")},
			},
		},
	}

	var wg sync.WaitGroup
	const numGoroutines = 50
	const opsPerGoroutine = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				tlsApp.EncryptedClientHello.configsMu.RLock()
				keys := tlsApp.EncryptedClientHello.stdlibReady
				tlsApp.EncryptedClientHello.configsMu.RUnlock()
				if len(keys) == 0 {
					t.Errorf("got empty stdlibReady keys")
				}
			}
		}()
	}

	wg.Wait()
}
