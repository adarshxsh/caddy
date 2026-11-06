package caddytls

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestCleanupUninitializedCache(t *testing.T) {
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

	err := tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("unexpected error during cleanup with nil cache: %v", err)
	}
}

func TestDeferredCacheEvictionOnReload(t *testing.T) {
	defer caddy.Stop()

	config1JSON := []byte(`{
		"apps": {
			"tls": {}
		}
	}`)

	config2JSON := []byte(`{
		"apps": {
			"tls": {}
		}
	}`)

	var cfg1, cfg2 caddy.Config
	if err := json.Unmarshal(config1JSON, &cfg1); err != nil {
		t.Fatalf("unmarshal config1 failed: %v", err)
	}
	if err := json.Unmarshal(config2JSON, &cfg2); err != nil {
		t.Fatalf("unmarshal config2 failed: %v", err)
	}

	err := caddy.Run(&cfg1)
	if err != nil {
		t.Fatalf("failed to run config1: %v", err)
	}

	err = caddy.Run(&cfg2)
	if err != nil {
		t.Fatalf("failed to run config2 (reload): %v", err)
	}
}

func TestCleanupWriteLockAndNilCheck(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	cacheOpts := certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
		},
	}
	certCache = certmagic.NewCache(cacheOpts)
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
		logger: zap.NewNop(),
		managing: map[string]string{
			"example.com": "issuer1",
		},
		loaded: map[string]string{
			"hash1": "cert1",
		},
	}

	// Verify Cleanup acquires write lock and completes safely without active next TLS app
	err := tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify certCache is set to nil after shutdown when no next TLS app is active
	certCacheMu.RLock()
	current := certCache
	certCacheMu.RUnlock()
	if current != nil {
		t.Errorf("expected certCache to be nil after cleanup without next TLS app")
	}
}

func TestAllMatchingCertificatesAndHasCertificateNilCache(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates when certCache is nil, got %v", certs)
	}

	tlsApp := &TLS{}
	hasCert := tlsApp.HasCertificateForSubject("example.com")
	if hasCert {
		t.Errorf("expected HasCertificateForSubject false when certCache is nil, got %v", hasCert)
	}
}

func TestConcurrentReadsDuringCleanup(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	cacheOpts := certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
		},
	}
	certCache = certmagic.NewCache(cacheOpts)
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
		logger: zap.NewNop(),
		managing: map[string]string{
			"concurrent.com": "issuer1",
		},
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = AllMatchingCertificates("concurrent.com")
					_ = tlsApp.HasCertificateForSubject("concurrent.com")
				}
			}
		}()
	}

	err := tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed under concurrent reads: %v", err)
	}

	close(stop)
	wg.Wait()
}
