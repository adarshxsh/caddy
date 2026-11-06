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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestTLS_Cleanup_NilCache(t *testing.T) {
	// Guarantee certCache is restored after test
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
		logger: zap.NewNop(),
	}

	// 1. Cleanup with nil certCache (shutdown path)
	if err := tlsApp.Cleanup(); err != nil {
		t.Fatalf("unexpected error during Cleanup with nil cache: %v", err)
	}

	// 2. AllMatchingCertificates with nil certCache
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates for nil cache, got: %v", certs)
	}

	// 3. HasCertificateForSubject with nil certCache
	hasCert := tlsApp.HasCertificateForSubject("example.com")
	if hasCert {
		t.Errorf("expected false for HasCertificateForSubject with nil cache, got true")
	}
}

func TestTLS_Cleanup_ReorderAndLock(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return &certmagic.Config{}, nil
		},
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

	// Create and provision new TLS app instance
	nextTLSApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"domain.com": "issuer2"},
		loaded:   map[string]string{},
	}
	ctxCtx := caddy.NewContextWithAppsForTest(map[string]caddy.App{
		"events": &caddyevents.App{},
		"tls":    nextTLSApp,
	})
	ctxCtx.Context = context.Background()
	ctx, cancel := caddy.NewContext(ctxCtx)
	defer cancel()
	if err := nextTLSApp.Provision(ctx); err != nil {
		t.Fatalf("Provision nextTLSApp failed: %v", err)
	}

	// Create old TLS app instance
	oldTLSApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"domain.com": "issuer1"},
		loaded:   map[string]string{},
	}

	testCtx := caddy.NewContextWithAppsForTest(map[string]caddy.App{
		"tls": nextTLSApp,
	})
	caddy.SetActiveContextForTest(testCtx)
	defer caddy.SetActiveContextForTest(caddy.Context{})

	// Call Cleanup on old app
	if err := oldTLSApp.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify certCache is still valid and not nil
	certCacheMu.RLock()
	cacheIsNil := (certCache == nil)
	certCacheMu.RUnlock()
	if cacheIsNil {
		t.Errorf("expected certCache to not be nil during reload Cleanup")
	}
}

func TestTLS_Cleanup_ConcurrentLookupsAndReloads(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return &certmagic.Config{}, nil
		},
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

	var stopCh = make(chan struct{})
	var wg sync.WaitGroup

	// Goroutine 1: Continuously query AllMatchingCertificates
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				_ = AllMatchingCertificates("example.com")
			}
		}
	}()

	// Goroutine 2: Continuously query HasCertificateForSubject
	tlsApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				_ = tlsApp.HasCertificateForSubject("example.com")
			}
		}
	}()

	// Main goroutine: Repeatedly run Cleanup on TLS apps
	for i := 0; i < 50; i++ {
		_ = tlsApp.Cleanup()
		time.Sleep(1 * time.Millisecond)
	}

	close(stopCh)
	wg.Wait()
}
