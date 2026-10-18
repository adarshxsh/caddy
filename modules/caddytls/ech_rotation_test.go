package caddytls

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// slowStorage wraps certmagic.Storage to simulate slow/blocking network storage.
type slowStorage struct {
	certmagic.Storage
	lockDelay time.Duration
	loadDelay time.Duration

	lockAcquired atomic.Bool
	unlockCalled atomic.Bool
}

func (s *slowStorage) Lock(ctx context.Context, name string) error {
	s.lockAcquired.Store(true)
	if s.lockDelay > 0 {
		time.Sleep(s.lockDelay)
	}
	return s.Storage.Lock(ctx, name)
}

func (s *slowStorage) Unlock(ctx context.Context, name string) error {
	s.unlockCalled.Store(true)
	return s.Storage.Unlock(ctx, name)
}

func (s *slowStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if s.loadDelay > 0 {
		time.Sleep(s.loadDelay)
	}
	return s.Storage.Load(ctx, key)
}

// failingStorage wraps certmagic.Storage to simulate storage errors.
type failingStorage struct {
	certmagic.Storage
	unlockCalled atomic.Bool
	failOnList   bool
}

func (f *failingStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if f.failOnList {
		return nil, errors.New("simulated storage list error")
	}
	return f.Storage.List(ctx, prefix, recursive)
}

func (f *failingStorage) Unlock(ctx context.Context, name string) error {
	f.unlockCalled.Store(true)
	return f.Storage.Unlock(ctx, name)
}

func TestECHRotation_NonBlockingHandshake(t *testing.T) {
	tmpDir := t.TempDir()
	fs := &certmagic.FileStorage{Path: tmpDir}
	slow := &slowStorage{
		Storage:   fs,
		lockDelay: 200 * time.Millisecond,
		loadDelay: 200 * time.Millisecond,
	}

	certmagic.Default.Storage = slow

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	_, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Artificially make key due for rotation
	ech.configsMu.Lock()
	for k := range ech.configs {
		for i := range ech.configs[k] {
			ech.configs[k][i].meta.Created = time.Now().Add(-24 * time.Hour * 31)
		}
	}
	ech.configsMu.Unlock()

	// Trigger rotation in background
	logger := zap.NewNop()
	rotationDone := make(chan error, 1)

	go func() {
		rotationDone <- ech.rotateECHKeys(caddyCtx, logger, false)
	}()

	// Give rotation a moment to acquire storage lock and enter slow storage calls
	time.Sleep(20 * time.Millisecond)

	// Simulate concurrent TLS handshakes getting ECH keys under RLock
	handshakeDone := make(chan time.Duration, 10)
	var wg sync.WaitGroup

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			ech.configsMu.RLock()
			_ = ech.stdlibReady
			ech.configsMu.RUnlock()
			handshakeDone <- time.Since(start)
		}()
	}

	wg.Wait()
	close(handshakeDone)

	for duration := range handshakeDone {
		if duration > 50*time.Millisecond {
			t.Errorf("Handshake wait time was %v, expected < 50ms (storage operations blocked handshake!)", duration)
		}
	}

	err = <-rotationDone
	if err != nil {
		t.Fatalf("rotateECHKeys failed: %v", err)
	}
}

func TestECHRotation_UnlocksStorageLockOnError(t *testing.T) {
	tmpDir := t.TempDir()
	fs := &certmagic.FileStorage{Path: tmpDir}

	certmagic.Default.Storage = fs

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	_, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Artificially make key due for rotation
	ech.configsMu.Lock()
	for k := range ech.configs {
		for i := range ech.configs[k] {
			ech.configs[k][i].meta.Created = time.Now().Add(-24 * time.Hour * 31)
		}
	}
	ech.configsMu.Unlock()

	failing := &failingStorage{
		Storage:    fs,
		failOnList: true,
	}
	certmagic.Default.Storage = failing

	logger := zap.NewNop()
	err = ech.rotateECHKeys(caddyCtx, logger, false)
	if err == nil {
		t.Fatal("expected rotation to fail on storage list error, but got nil")
	}

	if !failing.unlockCalled.Load() {
		t.Errorf("expected storage.Unlock to be called upon rotation error, but it was not")
	}
}

func TestECHRotation_KeyRotationAndDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	fs := &certmagic.FileStorage{Path: tmpDir}
	certmagic.Default.Storage = fs

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	_, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ech.configsMu.RLock()
	initialConfigCount := len(ech.configs["example.com"])
	initialKeyListCount := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if initialConfigCount != 1 || initialKeyListCount != 1 {
		t.Fatalf("expected 1 config initially, got %d configs and %d keys", initialConfigCount, initialKeyListCount)
	}

	// 1. Age key beyond 30 days -> should rotate
	ech.configsMu.Lock()
	cfgID := ech.configs["example.com"][0].ConfigID
	ech.configs["example.com"][0].meta.Created = time.Now().Add(-24 * time.Hour * 31)
	metaBytes, _ := json.Marshal(ech.configs["example.com"][0].meta)
	_ = fs.Store(caddyCtx, echMetaKey(cfgID), metaBytes)
	ech.configsMu.Unlock()

	logger := zap.NewNop()
	if err := ech.rotateECHKeys(caddyCtx, logger, false); err != nil {
		t.Fatalf("rotateECHKeys rotation step failed: %v", err)
	}

	ech.configsMu.RLock()
	rotatedConfigCount := len(ech.configs["example.com"])
	rotatedKeyListCount := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if rotatedConfigCount != 2 || rotatedKeyListCount != 2 {
		t.Fatalf("expected 2 configs after rotation, got %d configs and %d keys", rotatedConfigCount, rotatedKeyListCount)
	}

	// 2. Age replaced key beyond 90 days -> should delete expired key
	ech.configsMu.Lock()
	for i := range ech.configs["example.com"] {
		if !ech.configs["example.com"][i].meta.Replaced.IsZero() {
			ech.configs["example.com"][i].meta.Created = time.Now().Add(-24 * time.Hour * 91)
			metaB, _ := json.Marshal(ech.configs["example.com"][i].meta)
			_ = fs.Store(caddyCtx, echMetaKey(ech.configs["example.com"][i].ConfigID), metaB)
		}
	}
	ech.configsMu.Unlock()

	if err := ech.rotateECHKeys(caddyCtx, logger, false); err != nil {
		t.Fatalf("rotateECHKeys deletion step failed: %v", err)
	}

	ech.configsMu.RLock()
	finalConfigCount := len(ech.configs["example.com"])
	finalKeyListCount := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if finalConfigCount != 1 || finalKeyListCount != 1 {
		t.Fatalf("expected 1 config after deleting expired key, got %d configs and %d keys", finalConfigCount, finalKeyListCount)
	}
}
