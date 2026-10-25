package caddytls

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

func TestECHConcurrentRotationAndRead(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	initSlice := []tls.EncryptedClientHelloKey{}
	ech.stdlibReady.Store(&initSlice)

	// Populate dummy config
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("dummy-config-1"),
			privKeyBin: []byte("dummy-key-1"),
		},
	}
	ech.updateKeyList()

	tlsApp := &TLS{
		EncryptedClientHello: ech,
	}

	getKeys := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		keys := tlsApp.EncryptedClientHello.stdlibReady.Load()
		if keys == nil {
			return []tls.EncryptedClientHelloKey{}, nil
		}
		return *keys, nil
	}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Goroutines performing concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					keys, err := getKeys(nil)
					if err != nil {
						t.Errorf("unexpected error from getKeys: %v", err)
						return
					}
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
					}
				}
			}
		}()
	}

	// Goroutines performing concurrent updates (under lock as required by updateKeyList)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ech.configsMu.Lock()
				ech.configs["example.com"] = []echConfig{
					{
						configBin:  []byte("dummy-config-updated"),
						privKeyBin: []byte("dummy-key-updated"),
					},
				}
				ech.updateKeyList()
				ech.configsMu.Unlock()
			}
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	close(stopChan)
	wg.Wait()
}
