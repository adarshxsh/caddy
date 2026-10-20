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
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type mockStorage struct {
	mu       sync.Mutex
	data     map[string][]byte
	lockErr  error
	loadErr  error
	storeErr error
}

func (m *mockStorage) Lock(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lockErr
}

func (m *mockStorage) Unlock(ctx context.Context, name string) error {
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if val, ok := m.data[key]; ok {
		return val, nil
	}
	return nil, fs.ErrNotExist
}

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storeErr != nil {
		return m.storeErr
	}
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key] = value
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}

func TestSTEKBackoffDelay(t *testing.T) {
	tests := []struct {
		errCount int
		expected time.Duration
	}{
		{errCount: -1, expected: 5 * time.Second},
		{errCount: 0, expected: 5 * time.Second},
		{errCount: 1, expected: 5 * time.Second},
		{errCount: 2, expected: 10 * time.Second},
		{errCount: 3, expected: 20 * time.Second},
		{errCount: 4, expected: 40 * time.Second},
		{errCount: 5, expected: 80 * time.Second},
		{errCount: 6, expected: 160 * time.Second},
		{errCount: 7, expected: 5 * time.Minute},
		{errCount: 8, expected: 5 * time.Minute},
		{errCount: 100, expected: 5 * time.Minute},
	}

	for _, tt := range tests {
		delay := stekBackoffDelay(tt.errCount)
		if delay != tt.expected {
			t.Errorf("stekBackoffDelay(%d) = %v; want %v", tt.errCount, delay, tt.expected)
		}
	}
}

func TestDistributedSTEKRotationBackoffAndRecovery(t *testing.T) {
	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &Provider{
		storage:    storage,
		stekConfig: service,
		timer:      time.NewTimer(5 * time.Millisecond),
		ctx:        caddy.Context{Context: context.Background()},
	}

	doneChan := make(chan struct{})
	keysChan := make(chan [][32]byte, 10)

	// Inject storage lock error
	storage.mu.Lock()
	storage.lockErr = errors.New("simulated storage lock error")
	storage.mu.Unlock()

	go provider.rotate(doneChan, keysChan)

	// Trigger multiple failure ticks by resetting timer
	for i := 0; i < 3; i++ {
		time.Sleep(15 * time.Millisecond)
		provider.timer.Reset(5 * time.Millisecond)
	}

	select {
	case k := <-keysChan:
		t.Fatalf("expected no keys on error, received: %v", k)
	default:
	}

	// Clear storage lock error
	storage.mu.Lock()
	storage.lockErr = nil
	storage.mu.Unlock()

	// Reset timer to fire soon for recovery check
	provider.timer.Reset(5 * time.Millisecond)

	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Fatal("expected non-empty keys slice on recovery")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for keys after recovery")
	}

	close(doneChan)
}
