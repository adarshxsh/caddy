package caddytls

import (
	"sync"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestCleanup_NilCache(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()
	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	// Ensure calling functions on nil certCache doesn't panic
	certs := AllMatchingCertificates("example.com")
	if len(certs) != 0 {
		t.Errorf("expected empty certs slice for nil certCache, got %v", certs)
	}

	tlsApp := &TLS{}
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false for nil certCache")
	}

	// Cleanup when certCache is nil and no nextTLS
	err := tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("unexpected error from Cleanup with nil certCache: %v", err)
	}
}

func TestCleanup_ReorderAndExclusion(t *testing.T) {
	defer caddy.Stop()

	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		Capacity: 100,
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
		},
		Logger: zap.NewNop(),
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

	// Load active config to initialize caddy context with nextTLSApp
	cfg := []byte(`{"apps": {"tls": {}}}`)
	err := caddy.Load(cfg, false)
	if err != nil {
		t.Fatalf("failed to load caddy config: %v", err)
	}

	nextTLS, err := caddy.ActiveContext().AppIfConfigured("tls")
	if err != nil {
		t.Fatalf("failed to get active tls app: %v", err)
	}
	nextTLSApp := nextTLS.(*TLS)

	nextTLSApp.managingMu.Lock()
	nextTLSApp.managing = map[string]string{
		"remanaged.com": "issuer2", // different issuer -> reManage
		"kept.com":      "issuer1", // same issuer -> kept
	}
	nextTLSApp.managingMu.Unlock()

	oldApp := &TLS{
		managing: map[string]string{
			"remanaged.com": "issuer1",
			"removed.com":   "issuer1",
			"kept.com":      "issuer1",
		},
		logger: zap.NewNop(),
	}

	// Call Cleanup on oldApp
	err = oldApp.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify nextTLSApp has remanaged.com and kept.com in managing map
	nextTLSApp.managingMu.RLock()
	defer nextTLSApp.managingMu.RUnlock()

	if _, ok := nextTLSApp.managing["remanaged.com"]; !ok {
		t.Errorf("expected remanaged.com to be in nextTLSApp.managing")
	}
	if _, ok := nextTLSApp.managing["kept.com"]; !ok {
		t.Errorf("expected kept.com to be in nextTLSApp.managing")
	}
	if _, ok := nextTLSApp.managing["removed.com"]; ok {
		t.Errorf("expected removed.com not to be in nextTLSApp.managing")
	}
}

func TestCleanup_ConcurrentHandshakes(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		Capacity: 100,
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
		},
		Logger: zap.NewNop(),
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

	oldApp := &TLS{
		Automation: &AutomationConfig{
			defaultPublicAutomationPolicy: &AutomationPolicy{
				magic: certmagic.NewDefault(),
			},
		},
		managing: map[string]string{
			"site1.com": "issuer1",
			"site2.com": "issuer1",
		},
		logger: zap.NewNop(),
	}

	nextApp := &TLS{
		Automation: &AutomationConfig{
			defaultPublicAutomationPolicy: &AutomationPolicy{
				magic: certmagic.NewDefault(),
			},
		},
		managing: map[string]string{
			"site1.com": "issuer2",
			"site3.com": "issuer1",
		},
		logger: zap.NewNop(),
	}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Parallel queries while calling Cleanup and Manage
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					_ = AllMatchingCertificates("site1.com")
					_ = oldApp.HasCertificateForSubject("site1.com")
					_ = nextApp.HasCertificateForSubject("site1.com")
				}
			}
		}()
	}

	for reload := 0; reload < 20; reload++ {
		_ = oldApp.Cleanup()
		_ = nextApp.Manage(map[string]struct{}{"site1.com": {}})
	}

	close(stopChan)
	wg.Wait()
}
