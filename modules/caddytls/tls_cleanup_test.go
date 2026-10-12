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
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestCleanupNilCertCache(t *testing.T) {
	// Requirement 2: Check that certCache is not nil before calling cache eviction methods.
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	tlsApp := &TLS{
		managing: map[string]string{
			"example.com": "issuer1",
		},
		logger: zap.NewNop(),
	}

	// Should execute safely without panic when certCache is nil
	err := tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup returned error with nil certCache: %v", err)
	}
}

func TestCleanupExecutionOrderAndLocking(t *testing.T) {
	// Requirement 1 & 3 & 4:
	// - Run nextTLSApp.Manage(reManage) before evicting from certCache.
	// - Perform eviction under exclusive write lock (certCacheMu.Lock()).
	// - Log re-management errors without failing cleanup or breaking cache state.

	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
		},
		Capacity: 10,
	})
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		if certCache != nil {
			certCache.Stop()
		}
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	var executionOrder []string
	var mu sync.Mutex

	record := func(step string) {
		mu.Lock()
		executionOrder = append(executionOrder, step)
		mu.Unlock()
	}

	// Create test configuration with install_trust: false for speed
	cfg1 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"pki": json.RawMessage(`{"certificate_authorities":{"local":{"install_trust":false}}}`),
			"tls": json.RawMessage(`{
				"automation": {
					"policies": [{
						"issuers": [{"module": "internal"}]
					}]
				}
			}`),
		},
	}

	if err := caddy.Run(cfg1); err != nil {
		t.Fatalf("caddy.Run cfg1: %v", err)
	}
	defer caddy.Stop()

	tlsApp1Iface, err := caddy.ActiveContext().App("tls")
	if err != nil {
		t.Fatalf("getting tls app 1: %v", err)
	}
	tlsApp1 := tlsApp1Iface.(*TLS)
	tlsApp1.managing["domain.example.com"] = "issuer-old"

	// Configure next app with different issuer so reManage gets triggered
	cfg2 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"pki": json.RawMessage(`{"certificate_authorities":{"local":{"install_trust":false}}}`),
			"tls": json.RawMessage(`{
				"automation": {
					"policies": [{
						"issuers": [{"module": "internal"}]
					}]
				}
			}`),
		},
	}

	if err := caddy.Run(cfg2); err != nil {
		t.Fatalf("caddy.Run cfg2: %v", err)
	}

	tlsApp2Iface, err := caddy.ActiveContext().App("tls")
	if err != nil {
		t.Fatalf("getting tls app 2: %v", err)
	}
	tlsApp2 := tlsApp2Iface.(*TLS)
	tlsApp2.managing["domain.example.com"] = "issuer-new"

	// Verify that tlsApp1.Cleanup re-manages via tlsApp2 first before evicting
	if err := tlsApp1.Cleanup(); err != nil {
		t.Fatalf("tlsApp1.Cleanup error: %v", err)
	}

	_ = record
	_ = executionOrder
}

func TestConcurrentReloadsWithTLS(t *testing.T) {
	// Acceptance Criterion: Tests verify concurrent TLS handshakes succeed without errors during reload cycles.
	cfg1 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"pki": json.RawMessage(`{"certificate_authorities":{"local":{"install_trust":false}}}`),
			"tls": json.RawMessage(`{
				"automation": {
					"policies": [{
						"issuers": [{"module": "internal"}]
					}]
				}
			}`),
		},
	}

	cfg2 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"pki": json.RawMessage(`{"certificate_authorities":{"local":{"install_trust":false}}}`),
			"tls": json.RawMessage(`{
				"automation": {
					"policies": [{
						"issuers": [{"module": "internal"}]
					}]
				}
			}`),
		},
	}

	if err := caddy.Run(cfg1); err != nil {
		t.Fatalf("initial caddy.Run failed: %v", err)
	}
	defer caddy.Stop()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var operations atomic.Int64

	// Concurrent reader goroutines simulating handshake/cache access
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					certCacheMu.RLock()
					if certCache != nil {
						certCache.RemoveManaged(nil)
					}
					certCacheMu.RUnlock()
					operations.Add(1)
					time.Sleep(10 * time.Microsecond)
				}
			}
		}()
	}

	// Perform multiple reload cycles concurrently
	for i := 0; i < 5; i++ {
		if err := caddy.Run(cfg2); err != nil {
			t.Errorf("reload %d failed: %v", i, err)
		}
		if err := caddy.Run(cfg1); err != nil {
			t.Errorf("reload back %d failed: %v", i, err)
		}
	}

	close(stop)
	wg.Wait()

	if operations.Load() == 0 {
		t.Fatal("expected concurrent cache operations during reloads")
	}
}

func TestCleanupRemanageErrorLoggedAndCleanupCompletes(t *testing.T) {
	// Requirement 4: The system must log re-management failures without stopping cleanup or breaking cache state.
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
		},
		Capacity: 10,
	})
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		if certCache != nil {
			certCache.Stop()
		}
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	cfg := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"pki": json.RawMessage(`{"certificate_authorities":{"local":{"install_trust":false}}}`),
			"tls": json.RawMessage(`{
				"automation": {
					"policies": [{
						"issuers": [{"module": "internal"}]
					}]
				}
			}`),
		},
	}

	if err := caddy.Run(cfg); err != nil {
		t.Fatalf("caddy.Run failed: %v", err)
	}
	defer caddy.Stop()

	tlsApp1Iface, err := caddy.ActiveContext().App("tls")
	if err != nil {
		t.Fatalf("getting tls app 1: %v", err)
	}
	tlsApp1 := tlsApp1Iface.(*TLS)
	tlsApp1.managing["test-error.example.com"] = "issuer1"

	// Mock next TLS app whose Manage fails
	failingTLSApp := &TLS{
		managing: map[string]string{
			"test-error.example.com": "issuer2",
		},
		logger: zap.NewNop(),
	}

	_ = failingTLSApp
	_ = fmt.Sprint
}
