package caddytls

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(delayedStorageModule{})
}

type delayedStorageModule struct {
	Root    string `json:"root"`
	delay   time.Duration
	storage certmagic.Storage
}

func (d delayedStorageModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.test_delayed",
		New: func() caddy.Module { return new(delayedStorageModule) },
	}
}

func (d *delayedStorageModule) Provision(ctx caddy.Context) error {
	d.delay = 50 * time.Millisecond
	fs := &certmagic.FileStorage{Path: d.Root}
	d.storage = &delayedStorage{Storage: fs, delay: d.delay}
	return nil
}

func (d *delayedStorageModule) CertMagicStorage() (certmagic.Storage, error) {
	return d.storage, nil
}

type delayedStorage struct {
	certmagic.Storage
	delay time.Duration
}

func (d *delayedStorage) Lock(ctx context.Context, name string) error {
	time.Sleep(d.delay)
	return d.Storage.Lock(ctx, name)
}

func (d *delayedStorage) Unlock(ctx context.Context, name string) error {
	time.Sleep(d.delay)
	return d.Storage.Unlock(ctx, name)
}

func (d *delayedStorage) Store(ctx context.Context, key string, value []byte) error {
	time.Sleep(d.delay)
	return d.Storage.Store(ctx, key, value)
}

func (d *delayedStorage) Load(ctx context.Context, key string) ([]byte, error) {
	time.Sleep(d.delay)
	return d.Storage.Load(ctx, key)
}

func (d *delayedStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	time.Sleep(d.delay)
	return d.Storage.List(ctx, path, recursive)
}

func newTestContext(t *testing.T) caddy.Context {
	tmpDir := t.TempDir()
	cfg := &caddy.Config{
		StorageRaw: json.RawMessage(fmt.Sprintf(`{"module":"file_system","root":%q}`, tmpDir)),
	}
	caddyCtx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}
	return caddyCtx
}

func TestECHProvisionAndRotation(t *testing.T) {
	caddyCtx := newTestContext(t)

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
	}

	outerNames, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("ech.Provision failed: %v", err)
	}

	if len(outerNames) != 1 || outerNames[0] != "public.example.com" {
		t.Fatalf("unexpected outerNames: %v", outerNames)
	}

	ech.configsMu.RLock()
	if len(ech.stdlibReady) == 0 {
		t.Fatalf("expected stdlibReady to be populated after Provision")
	}
	cfg := ech.configs["public.example.com"][0]
	initialConfigID := cfg.ConfigID
	ech.configsMu.RUnlock()

	// Update metadata in storage to simulate key due for rotation (> 30 days old)
	agedMeta := echConfigMeta{
		Created: time.Now().Add(-31 * 24 * time.Hour),
	}
	metaBytes, err := json.Marshal(agedMeta)
	if err != nil {
		t.Fatalf("marshaling meta failed: %v", err)
	}
	if err := caddyCtx.Storage().Store(caddyCtx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
		t.Fatalf("storing aged meta failed: %v", err)
	}

	// Update in-memory metadata as well
	ech.configsMu.Lock()
	ech.configs["public.example.com"][0].meta = agedMeta
	ech.configsMu.Unlock()

	// Rotate keys
	logger := zap.NewNop()
	err = ech.rotateECHKeys(caddyCtx, logger, false)
	if err != nil {
		t.Fatalf("ech.rotateECHKeys failed: %v", err)
	}

	ech.configsMu.RLock()
	defer ech.configsMu.RUnlock()

	configs := ech.configs["public.example.com"]
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs after rotation, got %d", len(configs))
	}

	// Verify old config has Replaced timestamp set and new config was generated
	if configs[0].ConfigID == initialConfigID {
		if configs[0].meta.Replaced.IsZero() {
			t.Errorf("expected old config metadata Replaced to be set")
		}
	} else if configs[1].ConfigID == initialConfigID {
		if configs[1].meta.Replaced.IsZero() {
			t.Errorf("expected old config metadata Replaced to be set")
		}
	} else {
		t.Errorf("initial config ID %d not found in configs", initialConfigID)
	}

	// Verify stdlibReady has been updated
	if len(ech.stdlibReady) != 2 {
		t.Fatalf("expected stdlibReady to have 2 keys, got %d", len(ech.stdlibReady))
	}
}

func TestECHKeyRotation_LockingBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &caddy.Config{
		StorageRaw: json.RawMessage(fmt.Sprintf(`{"module":"test_delayed","root":%q}`, tmpDir)),
	}

	caddyCtx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "slowstorage.example.com"},
		},
	}

	_, err = ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ech.configsMu.RLock()
	cID := ech.configs["slowstorage.example.com"][0].ConfigID
	ech.configsMu.RUnlock()

	// Update metadata in storage to simulate key due for rotation
	agedMeta := echConfigMeta{
		Created: time.Now().Add(-31 * 24 * time.Hour),
	}
	metaBytes, err := json.Marshal(agedMeta)
	if err != nil {
		t.Fatalf("marshaling meta failed: %v", err)
	}
	if err := caddyCtx.Storage().Store(caddyCtx, echMetaKey(cID), metaBytes); err != nil {
		t.Fatalf("storing aged meta failed: %v", err)
	}

	ech.configsMu.Lock()
	ech.configs["slowstorage.example.com"][0].meta = agedMeta
	ech.configsMu.Unlock()

	// Start background rotation in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)

	logger := zap.NewNop()

	go func() {
		defer wg.Done()
		err := ech.rotateECHKeys(caddyCtx, logger, false)
		if err != nil {
			t.Errorf("rotateECHKeys failed: %v", err)
		}
	}()

	// Concurrently simulate TLS handshakes reading ECH keys
	// Verify that reading ECH keys via RLock never blocks for > 10ms even while storage I/O takes 50ms per operation
	stopHandshakes := make(chan struct{})
	maxHoldDuration := time.Duration(0)
	var holdMu sync.Mutex

	var handshakeWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		handshakeWg.Add(1)
		go func() {
			defer handshakeWg.Done()
			for {
				select {
				case <-stopHandshakes:
					return
				default:
					start := time.Now()
					ech.configsMu.RLock()
					_ = ech.stdlibReady
					ech.configsMu.RUnlock()
					dur := time.Since(start)

					holdMu.Lock()
					if dur > maxHoldDuration {
						maxHoldDuration = dur
					}
					holdMu.Unlock()

					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(stopHandshakes)
	handshakeWg.Wait()

	t.Logf("Maximum lock hold duration during slow storage key rotation: %v", maxHoldDuration)

	if maxHoldDuration > 10*time.Millisecond {
		t.Errorf("configsMu RLock blocked for %v during background key rotation (expected < 10ms)", maxHoldDuration)
	}
}

func TestECHKeyRotation_ExpiredDeletion(t *testing.T) {
	caddyCtx := newTestContext(t)

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "expired.example.com"},
		},
	}

	_, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ech.configsMu.RLock()
	cID := ech.configs["expired.example.com"][0].ConfigID
	ech.configsMu.RUnlock()

	// First rotate so we have a replaced key
	agedMeta := echConfigMeta{
		Created: time.Now().Add(-31 * 24 * time.Hour),
	}
	metaBytes, _ := json.Marshal(agedMeta)
	_ = caddyCtx.Storage().Store(caddyCtx, echMetaKey(cID), metaBytes)

	ech.configsMu.Lock()
	ech.configs["expired.example.com"][0].meta = agedMeta
	ech.configsMu.Unlock()

	logger := zap.NewNop()
	if err := ech.rotateECHKeys(caddyCtx, logger, false); err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	ech.configsMu.RLock()
	if len(ech.configs["expired.example.com"]) != 2 {
		t.Fatalf("expected 2 configs before deletion, got %d", len(ech.configs["expired.example.com"]))
	}
	// Find replaced config ID
	var replacedID uint8
	for i := range ech.configs["expired.example.com"] {
		if !ech.configs["expired.example.com"][i].meta.Replaced.IsZero() {
			replacedID = ech.configs["expired.example.com"][i].ConfigID
		}
	}
	ech.configsMu.RUnlock()

	// Update storage metadata for replaced config to age it beyond deleteAfter (> 90 days)
	expiredMeta := echConfigMeta{
		Created:  time.Now().Add(-91 * 24 * time.Hour),
		Replaced: time.Now().Add(-31 * 24 * time.Hour),
	}
	expMetaBytes, _ := json.Marshal(expiredMeta)
	_ = caddyCtx.Storage().Store(caddyCtx, echMetaKey(replacedID), expMetaBytes)

	ech.configsMu.Lock()
	for i := range ech.configs["expired.example.com"] {
		if ech.configs["expired.example.com"][i].ConfigID == replacedID {
			ech.configs["expired.example.com"][i].meta = expiredMeta
		}
	}
	ech.configsMu.Unlock()

	// Rotate keys (which should delete the expired key)
	if err := ech.rotateECHKeys(caddyCtx, logger, false); err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}

	ech.configsMu.RLock()
	defer ech.configsMu.RUnlock()

	if len(ech.configs["expired.example.com"]) != 1 {
		t.Fatalf("expected 1 config after expired deletion, got %d", len(ech.configs["expired.example.com"]))
	}
	if len(ech.stdlibReady) != 1 {
		t.Fatalf("expected stdlibReady to have 1 key after deletion, got %d", len(ech.stdlibReady))
	}
}
