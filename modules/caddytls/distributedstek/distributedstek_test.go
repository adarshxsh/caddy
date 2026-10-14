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
	"errors"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type mockStorage struct {
	fail atomic.Bool
	mu   sync.Mutex
	data map[string][]byte
}

func (m *mockStorage) Lock(ctx context.Context, name string) error {
	if m.fail.Load() {
		return errors.New("simulated storage lock error")
	}
	return nil
}

func (m *mockStorage) Unlock(ctx context.Context, name string) error {
	return nil
}

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	if m.fail.Load() {
		return errors.New("simulated storage store error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key] = value
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if m.fail.Load() {
		return nil, errors.New("simulated storage load error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	val, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return val, nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	if m.fail.Load() {
		return errors.New("simulated storage delete error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	if m.fail.Load() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok
}

func (m *mockStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}

func TestDistributedSTEKTimerResetOnTransientError(t *testing.T) {
	ms := &mockStorage{data: make(map[string][]byte)}
	p := &Provider{
		storage: ms,
		ctx:     caddy.Context{},
	}

	cfg := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(20 * time.Millisecond),
		MaxKeys:          4,
	}

	// Initialize with healthy storage
	initialKeys, err := p.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatalf("expected initial keys")
	}

	// Fail subsequent storage calls to simulate transient storage outage
	ms.fail.Store(true)

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := p.Next(doneChan)

	// Wait past one or more tick intervals while error persists
	time.Sleep(60 * time.Millisecond)

	// Verify no updated keys were emitted while in error state
	select {
	case k := <-keysChan:
		t.Fatalf("expected no keys during transient error, got: %v", k)
	default:
	}

	// Recover from transient storage outage
	ms.fail.Store(false)

	// Verify that the timer loop resumed and successfully emitted updated keys on next tick
	select {
	case updatedKeys := <-keysChan:
		if len(updatedKeys) == 0 {
			t.Fatalf("expected updated keys after recovery, got empty")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for distributed STEK rotation loop to recover after transient error")
	}
}
