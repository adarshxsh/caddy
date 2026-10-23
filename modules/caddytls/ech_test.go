package caddytls

import (
	"crypto/tls"
	"encoding/json"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func setupECHContext(t *testing.T) (caddy.Context, *TLS) {
	t.Helper()
	var cfg *caddy.Config
	err := json.Unmarshal([]byte(`{
		"apps": {
			"tls": {
				"encrypted_client_hello": {
					"configs": [{"public_name": "example.com"}]
				}
			}
		}
	}`), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("failed to provision context: %v", err)
	}
	appIface, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load tls app: %v", err)
	}
	tlsApp := appIface.(*TLS)
	return ctx, tlsApp
}

func TestGetEncryptedClientHelloKeys_Empty(t *testing.T) {
	ctx, tlsApp := setupECHContext(t)

	// Ensure stdlibReady is empty
	tlsApp.EncryptedClientHello.configsMu.Lock()
	tlsApp.EncryptedClientHello.stdlibReady = nil
	tlsApp.EncryptedClientHello.configsMu.Unlock()

	policies := ConnectionPolicies{{}}
	tlsCfg := policies.TLSConfig(ctx)

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

func TestGetEncryptedClientHelloKeys_DecoupledCopy(t *testing.T) {
	ctx, tlsApp := setupECHContext(t)

	tlsApp.EncryptedClientHello.configsMu.Lock()
	tlsApp.EncryptedClientHello.configs = map[string][]echConfig{
		"example.com": {
			{
				configBin:  []byte("config1"),
				privKeyBin: []byte("key1"),
			},
		},
	}
	tlsApp.EncryptedClientHello.updateKeyList()
	tlsApp.EncryptedClientHello.configsMu.Unlock()

	policies := ConnectionPolicies{{}}
	tlsCfg := policies.TLSConfig(ctx)

	keys1, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys1) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys1))
	}

	// Mutate key list in tlsApp
	tlsApp.EncryptedClientHello.configsMu.Lock()
	tlsApp.EncryptedClientHello.configs["example.com"] = append(tlsApp.EncryptedClientHello.configs["example.com"], echConfig{
		configBin:  []byte("config2"),
		privKeyBin: []byte("key2"),
	})
	tlsApp.EncryptedClientHello.updateKeyList()
	tlsApp.EncryptedClientHello.configsMu.Unlock()

	// Verify keys1 remains unchanged (decoupled copy)
	if len(keys1) != 1 {
		t.Fatalf("expected keys1 to retain length 1 after updateKeyList, got %d", len(keys1))
	}
	if string(keys1[0].Config) != "config1" {
		t.Fatalf("expected keys1[0].Config to be 'config1', got %s", keys1[0].Config)
	}

	// Fetch keys again and verify new content is present
	keys2, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys2) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys2))
	}
}

func TestGetEncryptedClientHelloKeys_Race(t *testing.T) {
	ctx, tlsApp := setupECHContext(t)

	tlsApp.EncryptedClientHello.configsMu.Lock()
	tlsApp.EncryptedClientHello.configs = map[string][]echConfig{
		"example.com": {
			{
				configBin:  []byte("config1"),
				privKeyBin: []byte("key1"),
			},
		},
	}
	tlsApp.EncryptedClientHello.updateKeyList()
	tlsApp.EncryptedClientHello.configsMu.Unlock()

	policies := ConnectionPolicies{{}}
	tlsCfg := policies.TLSConfig(ctx)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutines simulating crypto/tls reading ECH keys during handshakes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					keys, err := tlsCfg.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{})
					if err != nil {
						t.Errorf("GetEncryptedClientHelloKeys error: %v", err)
						return
					}
					// Simulate crypto/tls iterating over keys and reading properties outside lock
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
						_ = k.SendAsRetry
						if len(k.Config) > 0 {
							_ = k.Config[0]
						}
					}
				}
			}
		}()
	}

	// Goroutines simulating key rotation mutating stdlibReady under Lock
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tlsApp.EncryptedClientHello.configsMu.Lock()
				if j%2 == 0 {
					tlsApp.EncryptedClientHello.configs["example.com"] = []echConfig{
						{
							configBin:  []byte("config_a"),
							privKeyBin: []byte("key_a"),
						},
						{
							configBin:  []byte("config_b"),
							privKeyBin: []byte("key_b"),
						},
					}
				} else {
					tlsApp.EncryptedClientHello.configs["example.com"] = []echConfig{
						{
							configBin:  []byte("config_c"),
							privKeyBin: []byte("key_c"),
						},
					}
				}
				tlsApp.EncryptedClientHello.updateKeyList()
				tlsApp.EncryptedClientHello.configsMu.Unlock()
			}
		}(i)
	}

	// Let writers finish and then stop readers
	close(stop)
	wg.Wait()
}
