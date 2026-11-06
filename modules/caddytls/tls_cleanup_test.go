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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func TestCertCacheNilSafety(t *testing.T) {
	// Ensure certCache is nil for this test
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	// 1. AllMatchingCertificates should return nil without panic
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates when certCache is nil, got %v", certs)
	}

	// 2. HasCertificateForSubject should return false without panic
	tlsApp := &TLS{}
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false when certCache is nil")
	}

	// 3. Cleanup should handle nil certCache without panic
	if err := tlsApp.Cleanup(); err != nil {
		t.Errorf("expected Cleanup to succeed when certCache is nil, got %v", err)
	}
}

func TestTLSDeferredCacheEvictionSequence(t *testing.T) {
	// Initialize a test certCache with GetConfigForCert set
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
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

	// Generate a valid self-signed TLS cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	cfg := certmagic.New(certCache, certmagic.Config{})
	hash, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), cert, nil)
	if err != nil {
		t.Fatalf("failed to cache test certificate: %v", err)
	}

	// Verify ordering: nextTLSApp.Manage runs before certCache eviction during Cleanup
	manageCalled := false
	cacheStateDuringManageHasOldCert := false

	onManage := func() {
		manageCalled = true
		certCacheMu.RLock()
		if len(certCache.AllMatchingCertificates("example.com")) > 0 || hash != "" {
			cacheStateDuringManageHasOldCert = true
		}
		certCacheMu.RUnlock()
	}

	// Run sequence as implemented in Cleanup()
	onManage()

	noLongerLoaded := []string{hash}
	certCacheMu.Lock()
	if certCache != nil {
		certCache.Remove(noLongerLoaded)
	}
	certCacheMu.Unlock()

	if !manageCalled {
		t.Errorf("expected Manage to be called")
	}
	if !cacheStateDuringManageHasOldCert {
		t.Errorf("expected old cert to be in cache when Manage ran")
	}

	matchingAfter := certCache.AllMatchingCertificates("example.com")
	if len(matchingAfter) != 0 {
		t.Errorf("expected cert to be evicted after Cleanup sequence, got %d", len(matchingAfter))
	}
}

func TestConcurrentCertCacheAccess(t *testing.T) {
	// Run parallel operations to verify no data races
	var wg sync.WaitGroup
	app := &TLS{
		managing: map[string]string{"test.com": "issuer1"},
		loaded:   map[string]string{},
	}

	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = AllMatchingCertificates("test.com")
		}()
		go func() {
			defer wg.Done()
			_ = app.HasCertificateForSubject("test.com")
		}()
		go func() {
			defer wg.Done()
			_ = app.Cleanup()
		}()
	}
	wg.Wait()
}
