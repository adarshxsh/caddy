// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/tls"
	"encoding/json"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestGetEncryptedClientHelloKeysConcurrency(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	// Populate initial ECH configs and update stdlibReady
	ech.configsMu.Lock()
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("config1"),
			privKeyBin: []byte("key1"),
		},
	}
	ech.updateKeyList()
	ech.configsMu.Unlock()

	tlsApp := &TLS{
		EncryptedClientHello: ech,
	}

	// Construct callback function matching GetEncryptedClientHelloKeys in connpolicy.go
	getKeyFunc := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		tlsApp.EncryptedClientHello.configsMu.RLock()
		defer tlsApp.EncryptedClientHello.configsMu.RUnlock()
		if len(tlsApp.EncryptedClientHello.stdlibReady) == 0 {
			return nil, nil
		}
		keys := make([]tls.EncryptedClientHelloKey, len(tlsApp.EncryptedClientHello.stdlibReady))
		copy(keys, tlsApp.EncryptedClientHello.stdlibReady)
		return keys, nil
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Key rotation goroutine: updates ech.configs and calls updateKeyList under lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ech.configsMu.Lock()
			ech.configs["example.com"] = []echConfig{
				{
					configBin:  []byte("config_updated_1"),
					privKeyBin: []byte("key_updated_1"),
				},
				{
					configBin:  []byte("config_updated_2"),
					privKeyBin: []byte("key_updated_2"),
				},
			}
			ech.updateKeyList()
			ech.configsMu.Unlock()
		}
		close(done)
	}()

	// Handshake goroutines: concurrently call GetEncryptedClientHelloKeys and inspect slice elements
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					keys, err := getKeyFunc(nil)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
						return
					}
					// Simulate crypto/tls reading slice elements outside the lock
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
						_ = k.SendAsRetry
					}
				}
			}
		}()
	}

	wg.Wait()
}

func TestGetEncryptedClientHelloKeysTLSConfig(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
	}

	ech.configsMu.Lock()
	ech.configs["example.com"] = []echConfig{
		{
			configBin:  []byte("config1"),
			privKeyBin: []byte("key1"),
		},
	}
	ech.updateKeyList()
	ech.configsMu.Unlock()

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": json.RawMessage("{}"),
		},
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("failed to create caddy context: %v", err)
	}

	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*TLS)
	tlsApp.EncryptedClientHello = ech

	cp := ConnectionPolicies{
		&ConnectionPolicy{
			matchers: []ConnectionMatcher{MatchServerName{"example.com"}},
		},
	}

	tlsCfg := cp.TLSConfig(ctx)
	if tlsCfg.GetEncryptedClientHelloKeys == nil {
		t.Fatal("expected GetEncryptedClientHelloKeys callback to be non-nil")
	}

	keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error from GetEncryptedClientHelloKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if string(keys[0].Config) != "config1" {
		t.Fatalf("expected config1, got %s", string(keys[0].Config))
	}

	// Test nil/empty stdlibReady slice returns nil, nil
	ech.configsMu.Lock()
	ech.stdlibReady = nil
	ech.configsMu.Unlock()

	keysEmpty, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error from GetEncryptedClientHelloKeys on empty: %v", err)
	}
	if keysEmpty != nil {
		t.Fatalf("expected nil keys on empty stdlibReady, got %v", keysEmpty)
	}
}
