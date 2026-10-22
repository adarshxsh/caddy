package caddytls

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

func TestECH_GetEncryptedClientHelloKeys(t *testing.T) {
	var ech *ECH
	chi := &tls.ClientHelloInfo{ServerName: "example.com"}
	keys, err := ech.GetEncryptedClientHelloKeys(chi)
	if err != nil {
		t.Fatalf("unexpected error on nil ECH: %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil keys for nil ECH, got: %v", keys)
	}

	ech = &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	// Before updateKeyList, stdlibReady is nil
	keys, err = ech.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil keys before updateKeyList, got: %v", keys)
	}

	// Set up dummy config and update key list
	ech.configsMu.Lock()
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("config1"),
			privKeyBin: []byte("key1"),
			meta: echConfigMeta{
				Created: time.Now(),
			},
		},
	}
	ech.updateKeyList()
	ech.configsMu.Unlock()

	keys, err = ech.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got: %d", len(keys))
	}
	if string(keys[0].Config) != "config1" || string(keys[0].PrivateKey) != "key1" {
		t.Fatalf("unexpected key content: %+v", keys[0])
	}
}

func TestECH_ConcurrentGetKeysAndRotation(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	ech.configsMu.Lock()
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("initial_config"),
			privKeyBin: []byte("initial_key"),
			meta: echConfigMeta{
				Created: time.Now(),
			},
		},
	}
	ech.updateKeyList()
	ech.configsMu.Unlock()

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Spawn multiple reader goroutines calling GetEncryptedClientHelloKeys concurrently
	const numReaders = 10
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					keys, err := ech.GetEncryptedClientHelloKeys(nil)
					if err != nil {
						t.Errorf("unexpected error in reader goroutine: %v", err)
						return
					}
					if keys == nil {
						t.Errorf("expected non-nil keys in reader goroutine")
						return
					}
				}
			}
		}()
	}

	// Spawn writer goroutine updating key list concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			ech.configsMu.Lock()
			ech.configs["example.com"] = []echConfig{
				{
					configBin:  []byte("updated_config"),
					privKeyBin: []byte("updated_key"),
					meta: echConfigMeta{
						Created: time.Now(),
					},
				},
			}
			ech.updateKeyList()
			ech.configsMu.Unlock()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Wait for writer to finish then signal readers to stop
	time.Sleep(150 * time.Millisecond)
	close(done)
	wg.Wait()

	finalKeys, err := ech.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error getting final keys: %v", err)
	}
	if len(finalKeys) != 1 || string(finalKeys[0].Config) != "updated_config" {
		t.Fatalf("unexpected final keys: %+v", finalKeys)
	}
}
