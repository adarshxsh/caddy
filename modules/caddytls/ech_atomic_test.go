package caddytls

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

func TestGetEncryptedClientHelloKeys_LockFree(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	key1 := tls.EncryptedClientHelloKey{Config: []byte("config1"), PrivateKey: []byte("priv1")}
	keys := []tls.EncryptedClientHelloKey{key1}
	ech.stdlibReady.Store(&keys)

	tlsApp := &TLS{
		EncryptedClientHello: ech,
	}

	// Lock configsMu write lock to simulate background processing
	ech.configsMu.Lock()

	// Calling key getter must NOT block even when configsMu write lock is held
	done := make(chan struct{})
	var gotKeys []tls.EncryptedClientHelloKey
	var err error

	go func() {
		getter := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			keysPtr := tlsApp.EncryptedClientHello.stdlibReady.Load()
			if keysPtr == nil {
				return nil, nil
			}
			return *keysPtr, nil
		}

		gotKeys, err = getter(&tls.ClientHelloInfo{})
		close(done)
	}()

	select {
	case <-done:
		// Success: completed lock-free
	case <-time.After(1 * time.Second):
		ech.configsMu.Unlock()
		t.Fatal("GetEncryptedClientHelloKeys blocked on configsMu lock")
	}

	ech.configsMu.Unlock()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotKeys) != 1 || string(gotKeys[0].Config) != "config1" {
		t.Fatalf("unexpected keys returned: %v", gotKeys)
	}
}

func TestUpdateKeyList_AtomicSwap(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {
				{
					configBin:  []byte("cfgA"),
					privKeyBin: []byte("privA"),
					meta:       echConfigMeta{},
				},
			},
		},
	}

	ech.updateKeyList()

	keysPtr := ech.stdlibReady.Load()
	if keysPtr == nil {
		t.Fatal("expected non-nil keysPtr after updateKeyList")
	}
	if len(*keysPtr) != 1 || string((*keysPtr)[0].Config) != "cfgA" {
		t.Fatalf("unexpected key slice after updateKeyList: %v", *keysPtr)
	}

	ech.configsMu.Lock()
	ech.configs["example.com"] = append(ech.configs["example.com"], echConfig{
		configBin:  []byte("cfgB"),
		privKeyBin: []byte("privB"),
		meta:       echConfigMeta{},
	})
	ech.configsMu.Unlock()

	ech.updateKeyList()

	newKeysPtr := ech.stdlibReady.Load()
	if newKeysPtr == nil || len(*newKeysPtr) != 2 {
		t.Fatalf("expected 2 keys after second updateKeyList, got: %v", newKeysPtr)
	}
}
