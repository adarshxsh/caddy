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
	ctx, cancel := context.WithCancel(context.Background())
	tlsApp := &TLS{
		bgCtx:              ctx,
		bgCancel:           cancel,
		bgWg:               new(sync.WaitGroup),
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	// First Stop call should cancel the context and stop ticker
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if ctx.Err() == nil {
		t.Errorf("expected bgCtx to be canceled after Stop")
	}

	// Subsequent Stop calls must be idempotent and not panic
	for i := 0; i < 5; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Errorf("unexpected error on Stop iteration %d: %v", i, err)
		}
	}
}

func TestTLSStopConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
	}()

	tlsApp := &TLS{
		bgCtx:              ctx,
		bgCancel:           cancel,
		bgWg:               wg,
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	const goroutines = 20
	var testWg sync.WaitGroup
	testWg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer testWg.Done()
			if err := tlsApp.Stop(); err != nil {
				t.Errorf("unexpected error on concurrent Stop: %v", err)
			}
		}()
	}

	testWg.Wait()

	if ctx.Err() == nil {
		t.Errorf("expected bgCtx to be canceled after Stop")
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
