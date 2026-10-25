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

package distributedstek

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type mockStorage struct {
	certmagic.Storage
	mu        sync.Mutex
	failLocks int
}

func (m *mockStorage) Lock(ctx context.Context, name string) error {
	m.mu.Lock()
	if m.failLocks > 0 {
		m.failLocks--
		m.mu.Unlock()
		return fmt.Errorf("simulated storage lock failure")
	}
	m.mu.Unlock()
	return m.Storage.Lock(ctx, name)
}

func TestDistributedSTEK_TimerResetOnErrorAndShutdown(t *testing.T) {
	fileStore := &certmagic.FileStorage{Path: t.TempDir()}
	store := &mockStorage{
		Storage:   fileStore,
		failLocks: 0,
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{
		Context: context.Background(),
	})
	defer cancel()

	svc := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(20 * time.Millisecond),
		MaxKeys:          4,
	}

	p := &Provider{
		storage: store,
		ctx:     caddyCtx,
	}

	initialKeys, err := p.Initialize(svc)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatalf("expected initial keys, got empty slice")
	}

	// Set storage lock failure for the next timer tick in rotate()
	store.mu.Lock()
	store.failLocks = 1
	store.mu.Unlock()

	doneChan := make(chan struct{})
	keysChan := p.Next(doneChan)

	// Tick 1 will fail due to storage lock error.
	// Tick 2 will succeed due to deferred timer reset.
	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Errorf("received empty keys on successful rotation")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for distributed STEK rotation after transient error; timer reset on error likely failed")
	}

	// Clean shutdown test on doneChan
	close(doneChan)

	// Ensure clean exit without hang or panic
	time.Sleep(50 * time.Millisecond)
}
