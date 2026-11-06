package caddytls

import (
	"crypto/tls"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestUpdateKeyList(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {
				{
					configBin:  []byte("config1"),
					privKeyBin: []byte("key1"),
				},
			},
		},
	}

	ech.configsMu.Lock()
	ech.updateKeyList()
	ech.configsMu.Unlock()

	ech.configsMu.RLock()
	keys := slices.Clone(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if string(keys[0].Config) != "config1" {
		t.Errorf("unexpected config: %s", string(keys[0].Config))
	}
}

func TestConcurrentKeyRetrievalAndRotation(t *testing.T) {
	tlsApp := &TLS{
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			configs:   make(map[string][]echConfig),
		},
	}
	ech := tlsApp.EncryptedClientHello

	// Populate initial keys
	ech.configsMu.Lock()
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("initial_config"),
			privKeyBin: []byte("initial_key"),
		},
	}
	ech.updateKeyList()
	ech.configsMu.Unlock()

	getKeysCB := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		tlsApp.EncryptedClientHello.configsMu.RLock()
		defer tlsApp.EncryptedClientHello.configsMu.RUnlock()
		return slices.Clone(tlsApp.EncryptedClientHello.stdlibReady), nil
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Start readers simulating crypto/tls GetEncryptedClientHelloKeys
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chi := &tls.ClientHelloInfo{ServerName: "example.com"}
			for {
				select {
				case <-stopCh:
					return
				default:
					keys, err := getKeysCB(chi)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
						return
					}

					// Simulate crypto/tls iterating and reading returned slice elements
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
						_ = k.SendAsRetry
					}
				}
			}
		}()
	}

	// Start writers simulating updateKeyList / key rotation
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					ech.configsMu.Lock()
					ech.configs["example.com"] = []echConfig{
						{
							configBin:  []byte("config_update"),
							privKeyBin: []byte("key_update"),
						},
					}
					ech.updateKeyList()
					ech.configsMu.Unlock()
				}
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

func TestNilAndEmptyKeySliceClone(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
	}

	ech.configsMu.RLock()
	clonedNil := slices.Clone(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if clonedNil != nil {
		t.Errorf("expected nil for cloned nil slice, got %v", clonedNil)
	}

	ech.configsMu.Lock()
	ech.configs = make(map[string][]echConfig)
	ech.updateKeyList()
	ech.configsMu.Unlock()

	ech.configsMu.RLock()
	clonedEmpty := slices.Clone(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if len(clonedEmpty) != 0 {
		t.Errorf("expected empty slice, got len %d", len(clonedEmpty))
	}
}
