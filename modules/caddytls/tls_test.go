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
)

func TestTLSStopSequential(t *testing.T) {
	tlsApp := &TLS{
		storageCleanStop:   make(chan struct{}),
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	// First Stop call should close the channel and stop ticker
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsApp.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after Stop, got non-nil")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop, got non-nil")
	}

	// Subsequent Stop calls must be idempotent and not panic
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Errorf("unexpected error on Stop iteration %d: %v", i, err)
		}
	}
}

func TestTLSStopConcurrent(t *testing.T) {
	tlsApp := &TLS{
		storageCleanStop:   make(chan struct{}),
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := tlsApp.Stop(); err != nil {
				t.Errorf("unexpected error on concurrent Stop: %v", err)
			}
		}()
	}

	wg.Wait()

	if tlsApp.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after concurrent Stop, got non-nil")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after concurrent Stop, got non-nil")
	}
}

func TestTLSStopUninitialized(t *testing.T) {
	tlsApp := &TLS{}

	// Calling Stop on uninitialized TLS struct should not panic
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Errorf("unexpected error on uninitialized Stop iteration %d: %v", i, err)
		}
	}
}
