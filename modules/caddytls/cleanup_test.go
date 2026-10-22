package caddytls

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestNilCertCacheSafety(t *testing.T) {
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

	// 1. AllMatchingCertificates on nil certCache
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates slice, got %v", certs)
	}

	tlsApp := &TLS{
		logger:   zap.NewNop(),
		managing: make(map[string]string),
		loaded:   make(map[string]string),
	}

	// 2. HasCertificateForSubject on nil certCache
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false when certCache is nil")
	}

	// 3. Cleanup on nil certCache without active next TLS app
	err := tlsApp.Cleanup()
	if err != nil {
		t.Errorf("unexpected error during Cleanup on nil certCache: %v", err)
	}

	// Verify certCache is still nil after Cleanup
	certCacheMu.RLock()
	c := certCache
	certCacheMu.RUnlock()
	if c != nil {
		t.Errorf("expected certCache to remain nil after Cleanup, got %v", c)
	}
}

func TestCleanupReorderAndWriteLock(t *testing.T) {
	// Initialize a valid certCache
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return new(certmagic.Config), nil
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

	t1 := &TLS{
		logger: zap.NewNop(),
		managing: map[string]string{
			"example.com": "issuerA",
		},
		loaded: make(map[string]string),
	}

	// Simulate stopping t1 without a next TLS app
	err := t1.Cleanup()
	if err != nil {
		t.Fatalf("unexpected error during Cleanup: %v", err)
	}

	certCacheMu.RLock()
	currCache := certCache
	certCacheMu.RUnlock()
	if currCache != nil {
		t.Errorf("expected certCache to be nil after stopping last TLS app")
	}
}
