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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestTLSStopIdempotent(t *testing.T) {
	tlsApp := &TLS{
		storageCleanTicker: time.NewTicker(time.Hour),
		storageCleanStop:   make(chan struct{}),
	}

	// First Stop call should close channel and stop ticker
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsApp.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after Stop")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop")
	}

	// Subsequent Stop calls should execute safely without panicking
	for i := 0; i < 3; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on subsequent Stop (iteration %d): %v", i, err)
		}
	}
}

func TestTLSKeepStorageCleanStopIdempotent(t *testing.T) {
	tlsApp := &TLS{}
	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsApp.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	tlsApp.keepStorageClean()

	// Invoke Stop multiple times sequentially
	for i := 0; i < 3; i++ {
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on Stop (iteration %d): %v", i, err)
		}
	}

	if tlsApp.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after Stop")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop")
	}
}
