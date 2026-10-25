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
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestTLSStopRepeated(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed to create test context: %v", err)
	}

	tlsApp := &TLS{
		ctx:                 ctx,
		logger:              zap.NewNop(),
		DisableStorageClean: false,
	}

	// Initialize storage cleaner channel and ticker
	tlsApp.keepStorageClean()

	if tlsApp.storageCleanStop == nil {
		t.Fatal("expected storageCleanStop channel to be initialized")
	}
	if tlsApp.storageCleanTicker == nil {
		t.Fatal("expected storageCleanTicker to be initialized")
	}

	// First Stop call should close channel, stop ticker, and set pointers to nil
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop(): %v", err)
	}

	if tlsApp.storageCleanStop != nil {
		t.Error("expected storageCleanStop to be nil after Stop()")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Error("expected storageCleanTicker to be nil after Stop()")
	}

	// Repeated Stop calls sequentially should completed safely without panicking
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on repeated Stop() call %d: %v", i+1, err)
		}
	}

	// Concurrent Stop calls should also complete safely
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tlsApp.Stop(); err != nil {
				t.Errorf("unexpected error on concurrent Stop(): %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestTLSStopWithoutStorageClean(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed to create test context: %v", err)
	}

	tlsApp := &TLS{
		ctx:                 ctx,
		logger:              zap.NewNop(),
		DisableStorageClean: true,
	}

	// Repeated Stop calls on uninitialized cleaner should not panic
	for i := 0; i < 3; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on Stop(): %v", err)
		}
	}
}
