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

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestTLSStopIdempotent(t *testing.T) {
	t.Run("sequential calls with storage clean active", func(t *testing.T) {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		tlsApp := &TLS{
			ctx:    ctx,
			logger: zap.NewNop(),
		}
		tlsApp.keepStorageClean()

		// Call Stop multiple times sequentially
		for range 5 {
			if err := tlsApp.Stop(); err != nil {
				t.Fatalf("unexpected error calling Stop(): %v", err)
			}
		}
	})

	t.Run("concurrent calls with storage clean active", func(t *testing.T) {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		tlsApp := &TLS{
			ctx:    ctx,
			logger: zap.NewNop(),
		}
		tlsApp.keepStorageClean()

		var wg sync.WaitGroup
		const goroutines = 20
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := tlsApp.Stop(); err != nil {
					t.Errorf("unexpected error in concurrent Stop(): %v", err)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("sequential calls with nil channels", func(t *testing.T) {
		tlsApp := &TLS{
			logger: zap.NewNop(),
		}

		// Call Stop multiple times without initializing storage clean
		for range 3 {
			if err := tlsApp.Stop(); err != nil {
				t.Fatalf("unexpected error calling Stop(): %v", err)
			}
		}
	})

	t.Run("manually constructed channels", func(t *testing.T) {
		tlsApp := &TLS{
			logger:             zap.NewNop(),
			storageCleanOnce:   new(sync.Once),
			storageCleanStop:   make(chan struct{}),
			storageCleanTicker: time.NewTicker(1 * time.Hour),
		}

		for range 5 {
			if err := tlsApp.Stop(); err != nil {
				t.Fatalf("unexpected error calling Stop(): %v", err)
			}
		}
	})
}
