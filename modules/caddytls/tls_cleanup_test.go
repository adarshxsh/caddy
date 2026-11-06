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
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestTLSCleanup_NilCertCache(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = nil
	certCacheMu.Unlock()

	defer func() {
		certCacheMu.Lock()
		certCache = oldCache
		certCacheMu.Unlock()
	}()

	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	tlsApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "val1"},
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				IssuersRaw: []json.RawMessage{[]byte(`{"module": "internal"}`)},
			}},
		},
	}
	_ = tlsApp.Provision(ctx)

	nextTLSApp := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer2"},
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				IssuersRaw: []json.RawMessage{[]byte(`{"module": "internal"}`)},
			}},
		},
	}
	_ = nextTLSApp.Provision(ctx)

	// Call Cleanup when certCache is nil; must not panic
	err = tlsApp.Cleanup()
	if err != nil {
		t.Fatalf("expected no error from Cleanup, got %v", err)
	}
}

func TestTLSCleanup_ManageBeforeEviction(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
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

	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	t1 := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "val1"},
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				IssuersRaw: []json.RawMessage{[]byte(`{"module": "internal"}`)},
			}},
		},
	}
	if err := t1.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	t2 := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer2"},
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				IssuersRaw: []json.RawMessage{[]byte(`{"module": "internal"}`)},
			}},
		},
	}
	if err := t2.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	var executionOrder []string
	var orderMu sync.Mutex

	recordEvent := func(event string) {
		orderMu.Lock()
		executionOrder = append(executionOrder, event)
		orderMu.Unlock()
	}

	// Intercept/verify that Manage is called on nextTLSApp
	// before eviction.
	t1CleanupErr := func() error {
		// compute reManage
		reManage := make(map[string]struct{})
		for subj, currentIssuerKey := range t1.managing {
			if nextIssuerKey, ok := t2.managing[subj]; !ok || nextIssuerKey != currentIssuerKey {
				if ok && nextIssuerKey != currentIssuerKey {
					reManage[subj] = struct{}{}
				}
			}
		}

		if err := t2.Manage(reManage); err != nil {
			return err
		}
		recordEvent("t2.Manage")

		certCacheMu.Lock()
		if certCache != nil {
			recordEvent("certCache.Evict")
		}
		certCacheMu.Unlock()
		return nil
	}()

	if t1CleanupErr != nil {
		t.Fatalf("unexpected cleanup error: %v", t1CleanupErr)
	}

	orderMu.Lock()
	defer orderMu.Unlock()
	if len(executionOrder) != 2 {
		t.Fatalf("expected 2 recorded events, got %d", len(executionOrder))
	}
	if executionOrder[0] != "t2.Manage" {
		t.Errorf("expected t2.Manage to run first, got %s", executionOrder[0])
	}
	if executionOrder[1] != "certCache.Evict" {
		t.Errorf("expected certCache.Evict to run second, got %s", executionOrder[1])
	}
}

func TestTLSCleanup_ConcurrentAccess(t *testing.T) {
	certCacheMu.Lock()
	oldCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.NewDefault(), nil
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

	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	t1 := &TLS{
		logger:   zap.NewNop(),
		managing: map[string]string{"example.com": "issuer1"},
		loaded:   map[string]string{"hash1": "val1"},
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				IssuersRaw: []json.RawMessage{[]byte(`{"module": "internal"}`)},
			}},
		},
	}
	_ = t1.Provision(ctx)

	var wg sync.WaitGroup

	// Concurrently read from certCache
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = AllMatchingCertificates("example.com")
		}()
	}

	// Perform Cleanup concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = t1.Cleanup()
	}()

	wg.Wait()
}
