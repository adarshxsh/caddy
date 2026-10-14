package caddytls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func createTestTLSContext(t *testing.T, ech *ECH) caddy.Context {
	t.Helper()
	tlsApp := &TLS{
		EncryptedClientHello: ech,
	}
	tlsAppBytes, err := json.Marshal(tlsApp)
	if err != nil {
		t.Fatalf("failed to marshal TLS app: %v", err)
	}

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": tlsAppBytes,
		},
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("failed to create provision context: %v", err)
	}

	// Pre-load the tls app into context
	_, err = ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load tls app: %v", err)
	}

	return ctx
}

func TestGetEncryptedClientHelloKeys_DefensiveCopy(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
		stdlibReady: []tls.EncryptedClientHelloKey{
			{
				Config:      []byte("config1"),
				PrivateKey:  []byte("key1"),
				SendAsRetry: true,
			},
		},
	}

	ctx := createTestTLSContext(t, ech)

	cp := ConnectionPolicies{
		&ConnectionPolicy{},
	}

	tlsCfg := cp.TLSConfig(ctx)
	if tlsCfg.GetEncryptedClientHelloKeys == nil {
		t.Fatal("expected GetEncryptedClientHelloKeys callback to be set")
	}

	keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Mutate returned key byte slices
	keys[0].Config[0] = 'X'
	keys[0].PrivateKey[0] = 'Y'

	// Retrieve tlsApp from ctx to verify original internal stdlibReady was NOT mutated
	appIface, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to get tls app: %v", err)
	}
	loadedTLSApp := appIface.(*TLS)

	loadedTLSApp.EncryptedClientHello.configsMu.RLock()
	origConfig := loadedTLSApp.EncryptedClientHello.stdlibReady[0].Config
	origKey := loadedTLSApp.EncryptedClientHello.stdlibReady[0].PrivateKey
	loadedTLSApp.EncryptedClientHello.configsMu.RUnlock()

	if bytes.Equal(origConfig, keys[0].Config) {
		t.Fatal("expected original Config to be unmutated by caller changes")
	}
	if bytes.Equal(origKey, keys[0].PrivateKey) {
		t.Fatal("expected original PrivateKey to be unmutated by caller changes")
	}
}

func TestGetEncryptedClientHelloKeys_Empty(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
		stdlibReady: nil,
	}

	ctx := createTestTLSContext(t, ech)

	appIface, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to get tls app: %v", err)
	}
	loadedTLSApp := appIface.(*TLS)

	loadedTLSApp.EncryptedClientHello.configsMu.Lock()
	loadedTLSApp.EncryptedClientHello.stdlibReady = nil
	loadedTLSApp.EncryptedClientHello.configsMu.Unlock()

	cp := ConnectionPolicies{
		&ConnectionPolicy{},
	}

	tlsCfg := cp.TLSConfig(ctx)
	if tlsCfg.GetEncryptedClientHelloKeys == nil {
		t.Fatal("expected GetEncryptedClientHelloKeys callback to be set")
	}

	keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil keys for empty stdlibReady, got %v", keys)
	}
}

func TestGetEncryptedClientHelloKeys_ConcurrentRaceDetector(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs: []ECHConfiguration{
			{PublicName: "example.com"},
		},
		configs: map[string][]echConfig{
			"example.com": {
				{
					configBin:  []byte("config-data-1"),
					privKeyBin: []byte("private-key-1"),
				},
			},
		},
	}
	ech.updateKeyList()

	ctx := createTestTLSContext(t, ech)

	appIface, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to get tls app: %v", err)
	}
	loadedTLSApp := appIface.(*TLS)

	cp := ConnectionPolicies{
		&ConnectionPolicy{},
	}

	tlsCfg := cp.TLSConfig(ctx)
	if tlsCfg.GetEncryptedClientHelloKeys == nil {
		t.Fatal("expected GetEncryptedClientHelloKeys callback to be set")
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Launch reader goroutines that simulate crypto/tls handshakes reading keys
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
						return
					}
					// Read from the returned keys outside lock
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
						_ = k.SendAsRetry
					}
				}
			}
		}()
	}

	// Launch writer goroutine that updates keys concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			loadedTLSApp.EncryptedClientHello.configsMu.Lock()
			loadedTLSApp.EncryptedClientHello.configs["example.com"] = []echConfig{
				{
					configBin:  []byte("config-data-updated"),
					privKeyBin: []byte("private-key-updated"),
				},
			}
			loadedTLSApp.EncryptedClientHello.updateKeyList()
			loadedTLSApp.EncryptedClientHello.configsMu.Unlock()
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Wait for writer to finish, then signal readers to stop
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
