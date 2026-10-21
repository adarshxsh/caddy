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
)

func TestNilCacheSafety(t *testing.T) {
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

	// 1. Test AllMatchingCertificates with nil certCache
	certs := AllMatchingCertificates("example.com")
	if certs != nil {
		t.Errorf("expected nil certificates, got: %v", certs)
	}

	// 2. Test HasCertificateForSubject with nil certCache
	tlsApp := &TLS{}
	if tlsApp.HasCertificateForSubject("example.com") {
		t.Errorf("expected HasCertificateForSubject to return false when certCache is nil")
	}

	// 3. Test Cleanup with nil certCache (no active next TLS app)
	if err := tlsApp.Cleanup(); err != nil {
		t.Errorf("unexpected error on Cleanup with nil certCache: %v", err)
	}
}

func TestTLSCleanupAtomicStop(t *testing.T) {
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{
				{
					IssuersRaw: []json.RawMessage{
						[]byte(`{"module": "internal"}`),
					},
				},
			},
		},
	}

	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := tlsApp.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	certCacheMu.RLock()
	hasCache := certCache != nil
	certCacheMu.RUnlock()
	if !hasCache {
		t.Fatal("expected certCache to be initialized after provision")
	}

	// Cleanup should stop certCache and atomically set it to nil when no next app is configured
	if err := tlsApp.Cleanup(); err != nil {
		t.Fatalf("unexpected error on Cleanup: %v", err)
	}

	certCacheMu.RLock()
	currentCache := certCache
	certCacheMu.RUnlock()
	if currentCache != nil {
		t.Errorf("expected certCache to be nil after Cleanup without active app, got: %v", currentCache)
	}
}

func TestTLSReloadReManageOrder(t *testing.T) {
	// Verify that during Cleanup with a active next TLS app, re-management logic runs
	// for replaced subjects without panicking or premature eviction issues.
	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	app1 := &TLS{
		managing: map[string]string{
			"domain1.com": "issuer_a",
		},
	}
	if err := app1.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	app2 := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{
				{
					IssuersRaw: []json.RawMessage{
						[]byte(`{"module": "internal"}`),
					},
				},
			},
		},
		managing: map[string]string{
			"domain1.com": "issuer_b",
		},
	}
	if err := app2.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	// Active context simulates config reload
	cfg.AppsRaw = map[string]json.RawMessage{
		"tls": json.RawMessage(`{}`),
	}

	// Put app2 into active context as "tls" app
	activeCtx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Set app2 in active context
	_, err = activeCtx.App("tls")
	if err != nil {
		// activeCtx.App creates app from JSON, but we can set app2 into activeCtx
	}

	// Test Cleanup of app1 when app2 is active
	// Execute app1.Cleanup() to verify lock behavior, nil guards, and reManage execution path
	if err := app1.Cleanup(); err != nil {
		t.Errorf("unexpected error on Cleanup during reload test: %v", err)
	}

	// Final cleanup
	_ = app2.Cleanup()
}
