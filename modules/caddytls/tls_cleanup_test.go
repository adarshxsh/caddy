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
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func TestCertCacheNilGuards(t *testing.T) {
	// Ensure certCache is nil
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
		t.Errorf("expected false when certCache is nil")
	}

	// 3. Cleanup on nil cache (no new TLS app) should complete without panic
	if err := tlsApp.Cleanup(); err != nil {
		t.Errorf("unexpected error in Cleanup: %v", err)
	}
}

func TestCleanupHandoverSequence(t *testing.T) {
	// Create mock or real context for old and new TLS apps
	cfg1 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"tls": json.RawMessage(`{}`),
		},
	}

	if err := caddy.Run(cfg1); err != nil {
		t.Fatalf("failed to run cfg1: %v", err)
	}
	defer caddy.Stop()

	oldContext := caddy.ActiveContext()
	oldApp, err := oldContext.App("tls")
	if err != nil {
		t.Fatalf("failed to get old TLS app: %v", err)
	}
	oldTLS := oldApp.(*TLS)

	// Set up managing entries on oldTLS
	oldTLS.managing = map[string]string{
		"domain1.com": "issuerA",
		"domain2.com": "issuerB",
	}

	// Run new config so ActiveContext holds nextTLS
	cfg2 := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"tls": json.RawMessage(`{}`),
		},
	}
	if err := caddy.Run(cfg2); err != nil {
		t.Fatalf("failed to run cfg2: %v", err)
	}

	newContext := caddy.ActiveContext()
	newApp, err := newContext.App("tls")
	if err != nil {
		t.Fatalf("failed to get new TLS app: %v", err)
	}
	newTLS := newApp.(*TLS)
	newTLS.managing = map[string]string{
		"domain1.com": "issuerA",
		"domain2.com": "issuerC",
	}

	certCacheMu.Lock()
	if certCache == nil {
		certCache = certmagic.NewCache(certmagic.CacheOptions{})
	}
	certCacheMu.Unlock()

	// Verify Cleanup on oldTLS completes without error
	if err := oldTLS.Cleanup(); err != nil {
		t.Fatalf("oldTLS.Cleanup failed: %v", err)
	}
}
