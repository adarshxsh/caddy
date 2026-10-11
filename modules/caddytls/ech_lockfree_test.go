package caddytls

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap/zaptest"
)

var globalTestStorage certmagic.Storage

type mockStorageModule struct{}

func (mockStorageModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.mock_test",
		New: func() caddy.Module { return new(mockStorageModule) },
	}
}

func (mockStorageModule) CertMagicStorage() (certmagic.Storage, error) {
	return globalTestStorage, nil
}

// slowMockStorage wraps certmagic.FileStorage and adds artificial delay to Lock, Store, and List operations
type slowMockStorage struct {
	*certmagic.FileStorage
	delay time.Duration
}

func (s *slowMockStorage) Lock(ctx context.Context, name string) error {
	time.Sleep(s.delay)
	return s.FileStorage.Lock(ctx, name)
}

func (s *slowMockStorage) Store(ctx context.Context, key string, value []byte) error {
	time.Sleep(s.delay)
	return s.FileStorage.Store(ctx, key, value)
}

func (s *slowMockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	time.Sleep(s.delay)
	return s.FileStorage.List(ctx, prefix, recursive)
}

func init() {
	caddy.RegisterModule(mockStorageModule{})
}

func createTestContext(t *testing.T, storage certmagic.Storage) caddy.Context {
	t.Helper()
	globalTestStorage = storage

	var cfg caddy.Config
	cfg.StorageRaw = []byte(`{"module":"mock_test"}`)

	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("failed to provision context: %v", err)
	}

	return ctx
}

func TestECHLockFreeGetKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy_ech_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage := &certmagic.FileStorage{Path: tmpDir}
	ctx := createTestContext(t, storage)

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if len(outerNames) == 0 {
		t.Fatalf("expected outerNames, got empty")
	}

	keys := ech.GetKeys()
	if len(keys) == 0 {
		t.Fatalf("expected GetKeys() to return non-empty slice")
	}

	if len(keys) != len(ech.stdlibReady) {
		t.Fatalf("expected len %d, got %d", len(ech.stdlibReady), len(keys))
	}
}

func TestECHConcurrentHandshakeAndRotation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy_ech_concurrent_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	baseStorage := &certmagic.FileStorage{Path: tmpDir}
	slowStorage := &slowMockStorage{
		FileStorage: baseStorage,
		delay:       10 * time.Millisecond, // simulate 10ms storage operation latency
	}

	ctx := createTestContext(t, slowStorage)
	logger := zaptest.NewLogger(t)

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "cluster.example.com"},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	var wg sync.WaitGroup
	doneChan := make(chan struct{})

	var handshakeCount atomic.Uint64
	var maxHandshakeDurationNanos atomic.Int64

	// Spawn 20 simulated TLS client handshake goroutines reading ECH keys concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-doneChan:
					return
				default:
					start := time.Now()
					keys := ech.GetKeys()
					dur := time.Since(start).Nanoseconds()

					if len(keys) == 0 {
						t.Errorf("expected non-empty ECH keys during handshake")
					}

					handshakeCount.Add(1)
					for {
						currMax := maxHandshakeDurationNanos.Load()
						if dur <= currMax || maxHandshakeDurationNanos.CompareAndSwap(currMax, dur) {
							break
						}
					}

					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}

	// Simultaneously perform background key rotations with simulated storage delays
	for r := 0; r < 5; r++ {
		// Force rotation needed by marking existing keys created long ago
		ech.configsMu.Lock()
		for pName := range ech.configs {
			for idx := range ech.configs[pName] {
				ech.configs[pName][idx].meta.Created = time.Now().Add(-24 * time.Hour * 31)
			}
		}
		ech.configsMu.Unlock()

		err := ech.rotateECHKeys(ctx, logger, false)
		if err != nil {
			t.Fatalf("rotateECHKeys failed: %v", err)
		}
	}

	close(doneChan)
	wg.Wait()

	totalHandshakes := handshakeCount.Load()
	maxDur := time.Duration(maxHandshakeDurationNanos.Load())

	t.Logf("Completed %d concurrent handshakes during key rotation.", totalHandshakes)
	t.Logf("Max handshake key fetch duration: %v", maxDur)

	// Max duration for atomic GetKeys load should be well under 1 millisecond (typically <10 microseconds)
	// even though storage operations took 10+ ms each.
	if maxDur > 1*time.Millisecond {
		t.Errorf("Handshake key fetch took too long (%v), expected < 1ms lock-free execution", maxDur)
	}
}
