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
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type mockFailingStorage struct {
	underlying certmagic.Storage
	mu         sync.Mutex
	fail       bool
}

func (m *mockFailingStorage) Lock(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("simulated storage failure")
	}
	return m.underlying.Lock(ctx, name)
}

func (m *mockFailingStorage) Unlock(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("simulated storage failure")
	}
	return m.underlying.Unlock(ctx, name)
}

func (m *mockFailingStorage) Store(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("simulated storage failure")
	}
	return m.underlying.Store(ctx, key, value)
}

func (m *mockFailingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("simulated storage failure")
	}
	return m.underlying.Load(ctx, key)
}

func (m *mockFailingStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("simulated storage failure")
	}
	return m.underlying.Delete(ctx, key)
}

func (m *mockFailingStorage) Exists(ctx context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false
	}
	return m.underlying.Exists(ctx, key)
}

func (m *mockFailingStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("simulated storage failure")
	}
	return m.underlying.List(ctx, prefix, recursive)
}

func (m *mockFailingStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return certmagic.KeyInfo{}, errors.New("simulated storage failure")
	}
	return m.underlying.Stat(ctx, key)
}

func TestCalculateBackoff(t *testing.T) {
	itvl := 24 * time.Hour
	tests := []struct {
		failures int
		expected time.Duration
	}{
		{0, itvl},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{100, itvl},
	}

	for _, tc := range tests {
		got := calculateBackoff(tc.failures, itvl)
		if got != tc.expected {
			t.Errorf("calculateBackoff(%d, %v) = %v; want %v", tc.failures, itvl, got, tc.expected)
		}
	}

	shortItvl := 10 * time.Second
	gotShort := calculateBackoff(1, shortItvl)
	if gotShort != shortItvl {
		t.Errorf("calculateBackoff(1, %v) = %v; want %v", shortItvl, gotShort, shortItvl)
	}
}

func TestDistributedSTEKProvider_RotateRecovery(t *testing.T) {
	fsStorage := &certmagic.FileStorage{Path: t.TempDir()}
	mockStore := &mockFailingStorage{underlying: fsStorage}

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &Provider{
		storage: mockStore,
		ctx:     caddy.Context{},
	}

	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected initial keys")
	}

	doneChan := make(chan struct{})
	defer close(doneChan)

	// Simulate storage disconnect
	mockStore.mu.Lock()
	mockStore.fail = true
	mockStore.mu.Unlock()

	keysChan := provider.Next(doneChan)

	// Wait briefly while storage failure occurs during rotation tick
	time.Sleep(120 * time.Millisecond)

	// Simulate storage recovery (active state)
	mockStore.mu.Lock()
	mockStore.fail = false
	mockStore.mu.Unlock()

	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Errorf("expected non-empty keys after recovery")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("timed out waiting for key rotation recovery after storage reconnect")
	}
}
