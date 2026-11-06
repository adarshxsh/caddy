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
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestTLSStopRepeated(t *testing.T) {
	tlsApp := &TLS{
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	// Repeated sequential calls to Stop() should complete without panicking.
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on Stop call %d: %v", i+1, err)
		}
	}
}

func TestTLSStopConcurrent(t *testing.T) {
	tlsApp := &TLS{
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tlsApp.Stop(); err != nil {
				t.Errorf("unexpected error on concurrent Stop call: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestTLSStopNil(t *testing.T) {
	tlsApp := &TLS{}

	// Stop() when fields are nil should complete cleanly.
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on Stop with nil fields: %v", err)
	}
}

func TestTLSStopRepeatedWithStorageClean(t *testing.T) {
	ctx, err := caddy.ProvisionContext(new(caddy.Config))
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
		Automation: &AutomationConfig{
			StorageCleanInterval: caddy.Duration(1 * time.Hour),
		},
	}

	// Start storage cleaner
	tlsApp.keepStorageClean()

	// Repeated sequential and concurrent calls to Stop() should complete without panicking
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on Stop call %d: %v", i+1, err)
		}
	}
}

