package caddytls

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestNilCertCacheSafety(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()
	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	// Test AllMatchingCertificates with nil certCache
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates for nil certCache, got %v", certs)
	}

	// Test HasCertificateForSubject with nil certCache
	tlsApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "loader1"},
	}
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false for nil certCache")
	}

	// Test Cleanup with nil certCache (no next app configured)
	err := tlsApp.Cleanup()
	if err != nil {
		t.Errorf("unexpected error during Cleanup with nil certCache: %v", err)
	}
}

func TestCleanupReManageBeforeEvictionOrder(t *testing.T) {
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

	// Prepare config with new TLS app
	nextTLSApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer2"},
		loaded:   map[string]string{},
	}
	rawNextTLS, err := json.Marshal(nextTLSApp)
	if err != nil {
		t.Fatalf("marshaling next TLS app: %v", err)
	}

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": rawNextTLS,
		},
	}

	if err := caddy.Run(cfg); err != nil {
		t.Fatalf("running caddy config: %v", err)
	}
	defer caddy.Stop()

	// Current TLS app being stopped/cleaned up
	currentTLSApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "loader1"},
	}

	// Run Cleanup on current TLS app
	if err := currentTLSApp.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}

func TestConcurrentCacheAccessAndCleanup(t *testing.T) {
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

	tlsApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "loader1"},
	}

	var wg sync.WaitGroup
	const numGoroutines = 20
	const iterations = 100

	// Concurrent readers calling AllMatchingCertificates and HasCertificateForSubject
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = AllMatchingCertificates("example.com")
				_ = tlsApp.HasCertificateForSubject("example.com")
			}
		}()
	}

	// Concurrent cleanup calls
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations/10; j++ {
				_ = tlsApp.Cleanup()
			}
		}()
	}

	wg.Wait()
}
