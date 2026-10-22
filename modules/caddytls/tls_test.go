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
	stopChan := make(chan struct{})
	ticker := time.NewTicker(time.Hour)
	tlsModule := &TLS{
		storageCleanStop:   stopChan,
		storageCleanTicker: ticker,
	}

	// First stop call
	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsModule.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after Stop, got %v", tlsModule.storageCleanStop)
	}
	if tlsModule.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop, got %v", tlsModule.storageCleanTicker)
	}

	// Verify original channel was closed
	select {
	case _, open := <-stopChan:
		if open {
			t.Errorf("expected storageCleanStop channel to be closed")
		}
	default:
		t.Errorf("expected storageCleanStop channel to receive close signal")
	}

	// Second stop call (must be idempotent and not panic)
	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on second Stop: %v", err)
	}

	// Third stop call
	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on third Stop: %v", err)
	}
}

func TestTLSStopConcurrent(t *testing.T) {
	stopChan := make(chan struct{})
	ticker := time.NewTicker(time.Hour)
	tlsModule := &TLS{
		storageCleanStop:   stopChan,
		storageCleanTicker: ticker,
	}

	var wg sync.WaitGroup
	const numGoroutines = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tlsModule.Stop(); err != nil {
				t.Errorf("unexpected error on concurrent Stop: %v", err)
			}
		}()
	}

	wg.Wait()

	if tlsModule.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after concurrent Stop, got %v", tlsModule.storageCleanStop)
	}
	if tlsModule.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after concurrent Stop, got %v", tlsModule.storageCleanTicker)
	}

	// Verify channel was closed
	select {
	case _, open := <-stopChan:
		if open {
			t.Errorf("expected storageCleanStop channel to be closed")
		}
	default:
		t.Errorf("expected storageCleanStop channel to receive close signal")
	}
}

func TestTLSStopNilPointers(t *testing.T) {
	tlsModule := &TLS{}

	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on Stop with nil pointers: %v", err)
	}

	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on second Stop with nil pointers: %v", err)
	}
}
