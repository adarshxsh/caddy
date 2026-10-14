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
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func generateTestCert(domain string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestTLSAppCleanupNilCertCache(t *testing.T) {
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
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": ""},
	}

	// Make sure AllMatchingCertificates and HasCertificateForSubject don't panic when certCache is nil
	if certs := AllMatchingCertificates("example.com"); certs != nil {
		t.Errorf("expected nil certificates when certCache is nil, got %v", certs)
	}
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected false from HasCertificateForSubject when certCache is nil")
	}

	// Test Cleanup when no active context TLS app exists and certCache is nil
	if err := tlsApp.Cleanup(); err != nil {
		t.Fatalf("unexpected error during Cleanup with nil certCache: %v", err)
	}
}

func TestTLSAppCleanupOrderAndLocking(t *testing.T) {
	// Initialize certCache
	certCacheMu.Lock()
	if certCache == nil {
		certCache = certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return certmagic.NewDefault(), nil
			},
			Capacity: 100,
		})
	}
	certCacheMu.Unlock()

	// Load a test certificate into certCache
	tlsCert, err := generateTestCert("example.com")
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	certCacheMu.RLock()
	magic := certmagic.New(certCache, certmagic.Config{})
	certCacheMu.RUnlock()

	_, err = magic.CacheUnmanagedTLSCertificate(context.Background(), tlsCert, nil)
	if err != nil {
		t.Fatalf("failed to cache cert: %v", err)
	}

	// Load first Caddy configuration with TLS app
	cfgJSON1 := []byte(`{
		"admin": {"disabled": true},
		"apps": {
			"tls": {
				"certificates": {
					"automate": ["example.com"]
				},
				"automation": {
					"policies": [
						{
							"subjects": ["example.com"],
							"issuers": [{"module": "internal"}]
						}
					]
				}
			}
		}
	}`)

	err = caddy.Load(cfgJSON1, false)
	if err != nil {
		t.Fatalf("failed to load first config: %v", err)
	}

	// Load second Caddy configuration with updated TLS app
	cfgJSON2 := []byte(`{
		"admin": {"disabled": true},
		"apps": {
			"tls": {
				"certificates": {
					"automate": ["example.com", "other.example.com"]
				},
				"automation": {
					"policies": [
						{
							"subjects": ["example.com"],
							"issuers": [{"module": "internal"}]
						},
						{
							"subjects": ["other.example.com"],
							"issuers": [{"module": "internal"}]
						}
					]
				}
			}
		}
	}`)

	err = caddy.Load(cfgJSON2, false)
	if err != nil {
		t.Fatalf("failed to load second config: %v", err)
	}

	// Verify that the active TLS app is running and managing example.com
	activeTLS, err := caddy.ActiveContext().AppIfConfigured("tls")
	if err != nil || activeTLS == nil {
		t.Fatalf("expected active TLS app after reload, got err: %v", err)
	}

	tlsApp := activeTLS.(*TLS)
	if _, ok := tlsApp.managing["example.com"]; !ok {
		t.Errorf("expected example.com to be managed after config reload")
	}

	caddy.Stop()
}

func TestTLSHandshakeAndReloadConcurrency(t *testing.T) {
	// Initialize certCache
	certCacheMu.Lock()
	if certCache == nil {
		certCache = certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return certmagic.NewDefault(), nil
			},
			Capacity: 1000,
		})
	}
	certCacheMu.Unlock()

	tlsCert, err := generateTestCert("concurrent.example.com")
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	certCacheMu.RLock()
	magic := certmagic.New(certCache, certmagic.Config{})
	certCacheMu.RUnlock()

	_, err = magic.CacheUnmanagedTLSCertificate(context.Background(), tlsCert, nil)
	if err != nil {
		t.Fatalf("failed to cache cert: %v", err)
	}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Concurrent readers doing certificate lookups (simulating TLS handshakes)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					_ = AllMatchingCertificates("concurrent.example.com")
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Concurrent reload / cleanup triggers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oldApp := &TLS{
				managing: map[string]string{"concurrent.example.com": "issuer1"},
			}
			newApp := &TLS{
				managing: map[string]string{"concurrent.example.com": "issuer2"},
			}

			// Perform Cleanup which evicts under write lock and calls Manage
			_ = oldApp.Cleanup()
			_ = newApp.Cleanup()
			time.Sleep(2 * time.Millisecond)
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stopChan)
	wg.Wait()
}
