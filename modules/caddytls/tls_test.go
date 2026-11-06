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
	"sync"
	"testing"
	"time"
)

func TestTLSStopSequential(t *testing.T) {
	bgCtx, bgCancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(time.Hour)
	var bgWg sync.WaitGroup
	bgWg.Add(1)
	go func() {
		<-bgCtx.Done()
		bgWg.Done()
	}()

	tlsModule := &TLS{
		bgCtx:              bgCtx,
		bgCancel:           bgCancel,
		bgWg:               &bgWg,
		storageCleanTicker: ticker,
	}

	// First stop call
	if err := tlsModule.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsModule.bgCancel != nil {
		t.Errorf("expected bgCancel to be nil after Stop, got %v", tlsModule.bgCancel)
	}
	if tlsModule.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop, got %v", tlsModule.storageCleanTicker)
	}

	// Verify context was canceled
	select {
	case <-bgCtx.Done():
	default:
		t.Errorf("expected bgCtx to be canceled")
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
	bgCtx, bgCancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(time.Hour)
	var bgWg sync.WaitGroup
	bgWg.Add(1)
	go func() {
		<-bgCtx.Done()
		bgWg.Done()
	}()

	tlsModule := &TLS{
		bgCtx:              bgCtx,
		bgCancel:           bgCancel,
		bgWg:               &bgWg,
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

	if tlsModule.bgCancel != nil {
		t.Errorf("expected bgCancel to be nil after concurrent Stop, got %v", tlsModule.bgCancel)
	}
	if tlsModule.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after concurrent Stop, got %v", tlsModule.storageCleanTicker)
	}

	// Verify context was canceled
	select {
	case <-bgCtx.Done():
	default:
		t.Errorf("expected bgCtx to be canceled")
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
