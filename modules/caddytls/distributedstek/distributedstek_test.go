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
	mu       sync.Mutex
	data     map[string][]byte
	failLock bool
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		data: make(map[string][]byte),
	}
}

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return v, nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok
}

func (m *mockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}

func (m *mockStorage) Lock(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failLock {
		return errors.New("lock failed")
	}
	return nil
}

func (m *mockStorage) Unlock(ctx context.Context, name string) error {
	return nil
}

func TestDistributedSTEKRotationBackoff(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          4,
	}

	ms := newMockStorage()
	p := &Provider{
		storage:    ms,
		stekConfig: service,
		ctx:        caddy.Context{},
	}

	keys, err := p.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("expected initial keys, got empty")
	}

	doneChan := make(chan struct{})
	keysChan := p.Next(doneChan)

	// Simulate storage locking failure
	ms.mu.Lock()
	ms.failLock = true
	ms.mu.Unlock()

	// Wait for a backoff cycle on failure
	time.Sleep(30 * time.Millisecond)

	if atomic.LoadInt32(&p.numFailures) == 0 {
		t.Errorf("expected numFailures > 0 after storage error")
	}

	// Restore storage functionality
	ms.mu.Lock()
	ms.failLock = false
	ms.mu.Unlock()

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("expected updated keys after recovery, got empty")
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("timeout waiting for updated keys after recovery")
	}

	if nf := atomic.LoadInt32(&p.numFailures); nf != 0 {
		t.Errorf("expected numFailures reset to 0 after success, got %d", nf)
	}

	close(doneChan)
}
