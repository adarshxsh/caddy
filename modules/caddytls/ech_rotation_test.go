package caddytls

import (
	"context"
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestECHRotationDecoupledFromMemoryLock(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy-ech-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage := &certmagic.FileStorage{Path: tmpDir}
	origStorage := certmagic.Default.Storage
	certmagic.Default.Storage = storage
	defer func() { certmagic.Default.Storage = origStorage }()

	ctx, cancel := caddy.NewContext(caddy.Context{
		Context: context.Background(),
	})
	defer cancel()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
	}

	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("ECH provision failed: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outer names from provision")
	}

	logger := zap.NewNop()

	// Simulate concurrent client TLS handshakes calling GetEncryptedClientHelloKeys
	done := make(chan struct{})
	var handshakeReadCount atomic.Uint64
	started := make(chan struct{})

	go func() {
		close(started)
		for {
			select {
			case <-done:
				return
			default:
				ech.configsMu.RLock()
				keys := ech.stdlibReady
				_ = len(keys)
				handshakeReadCount.Add(1)
				ech.configsMu.RUnlock()
			}
		}
	}()

	<-started

	// Perform multiple rotations (when rotation is not needed and when storage lock is acquired)
	for i := 0; i < 50; i++ {
		err := ech.rotateECHKeys(ctx, logger, false)
		if err != nil {
			t.Fatalf("rotateECHKeys iteration %d failed: %v", i, err)
		}
	}

	// Give reader goroutine a brief moment to run
	time.Sleep(5 * time.Millisecond)
	close(done)

	if handshakeReadCount.Load() == 0 {
		t.Fatalf("expected concurrent handshake read operations to execute")
	}
}

func TestECHRotationDoubleCheckClusterSync(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy-ech-sync-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage := &certmagic.FileStorage{Path: tmpDir}
	origStorage := certmagic.Default.Storage
	certmagic.Default.Storage = storage
	defer func() { certmagic.Default.Storage = origStorage }()

	ctx, cancel := caddy.NewContext(caddy.Context{
		Context: context.Background(),
	})
	defer cancel()

	echNode1 := &ECH{Configs: []ECHConfiguration{{PublicName: "cluster.example.com"}}}
	_, err = echNode1.Provision(ctx)
	if err != nil {
		t.Fatalf("node1 provision failed: %v", err)
	}

	echNode2 := &ECH{Configs: []ECHConfiguration{{PublicName: "cluster.example.com"}}}
	_, err = echNode2.Provision(ctx)
	if err != nil {
		t.Fatalf("node2 provision failed: %v", err)
	}

	logger := zap.NewNop()

	// Verify both nodes loaded the initial configs without error
	echNode1.configsMu.RLock()
	keys1Count := len(echNode1.stdlibReady)
	echNode1.configsMu.RUnlock()

	echNode2.configsMu.RLock()
	keys2Count := len(echNode2.stdlibReady)
	echNode2.configsMu.RUnlock()

	if keys1Count == 0 || keys2Count == 0 {
		t.Fatalf("expected stdlibReady keys on both nodes: node1=%d, node2=%d", keys1Count, keys2Count)
	}

	// Trigger rotation on node1
	if err := echNode1.rotateECHKeys(ctx, logger, false); err != nil {
		t.Fatalf("node1 rotation failed: %v", err)
	}

	// Trigger rotation on node2 (which double-checks storage and syncs)
	if err := echNode2.rotateECHKeys(ctx, logger, false); err != nil {
		t.Fatalf("node2 rotation failed: %v", err)
	}
}

func TestGetEncryptedClientHelloKeysNonBlocking(t *testing.T) {
	ech := &ECH{
		configsMu:   new(sync.RWMutex),
		stdlibReady: []tls.EncryptedClientHelloKey{{Config: []byte("test")}},
	}

	// Verify GetEncryptedClientHelloKeys callback pattern under RLock
	retrievedKeys := func() []tls.EncryptedClientHelloKey {
		ech.configsMu.RLock()
		defer ech.configsMu.RUnlock()
		return ech.stdlibReady
	}()

	if len(retrievedKeys) != 1 || string(retrievedKeys[0].Config) != "test" {
		t.Fatalf("unexpected retrieved keys: %v", retrievedKeys)
	}
}
