package caddytls

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestCleanupReorderingAndWriteLock(t *testing.T) {
	// Initialize certCache
	certCacheMu.Lock()
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
		},
		Logger: zap.NewNop(),
	})
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		if certCache != nil {
			certCache.Stop()
			certCache = nil
		}
		certCacheMu.Unlock()
	}()

	// Construct two configs with "tls" app
	cfg1JSON := []byte(`{
		"apps": {
			"tls": {
				"certificates": {
					"automate": ["example.com"]
				}
			}
		}
	}`)

	cfg2JSON := []byte(`{
		"apps": {
			"tls": {
				"certificates": {
					"automate": ["example.com", "other.com"]
				}
			}
		}
	}`)

	var cfg1, cfg2 caddy.Config
	if err := json.Unmarshal(cfg1JSON, &cfg1); err != nil {
		t.Fatalf("unmarshaling cfg1: %v", err)
	}
	if err := json.Unmarshal(cfg2JSON, &cfg2); err != nil {
		t.Fatalf("unmarshaling cfg2: %v", err)
	}

	if err := caddy.Run(&cfg1); err != nil {
		t.Fatalf("running cfg1: %v", err)
	}

	if err := caddy.Run(&cfg2); err != nil {
		t.Fatalf("running cfg2: %v", err)
	}

	// Stop caddy
	if err := caddy.Stop(); err != nil {
		t.Fatalf("stopping caddy: %v", err)
	}
}

func TestNilCacheGuards(t *testing.T) {
	certCacheMu.Lock()
	certCache = nil
	certCacheMu.Unlock()

	tls := &TLS{
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": ""},
		logger:   zap.NewNop(),
	}

	// Ensure HasCertificateForSubject does not panic when certCache is nil
	if tls.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false when certCache is nil")
	}

	// Ensure AllMatchingCertificates does not panic when certCache is nil
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected AllMatchingCertificates to return nil when certCache is nil")
	}

	// Ensure Cleanup does not panic when certCache is nil
	err := tls.Cleanup()
	if err != nil {
		t.Errorf("unexpected error during Cleanup with nil certCache: %v", err)
	}
}

func TestTeardownWriteLock(t *testing.T) {
	certCacheMu.Lock()
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
		},
		Logger: zap.NewNop(),
	})
	certCacheMu.Unlock()

	tls := &TLS{
		logger: zap.NewNop(),
	}

	// When no TLS app is configured in ActiveContext, Cleanup should stop certCache and set it to nil
	err := tls.Cleanup()
	if err != nil {
		t.Fatalf("unexpected error during Cleanup: %v", err)
	}

	certCacheMu.RLock()
	cacheIsNil := certCache == nil
	certCacheMu.RUnlock()

	if !cacheIsNil {
		t.Errorf("expected certCache to be nil after Cleanup teardown")
	}
}
