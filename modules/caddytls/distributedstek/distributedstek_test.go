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

type failingStorage struct {
	certmagic.Storage
	mu       sync.Mutex
	failLoad bool
}

func (fs *failingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.failLoad {
		return nil, fmt.Errorf("transient storage error")
	}
	return fs.Storage.Load(ctx, key)
}

func TestDistributedSTEKRotationRetry(t *testing.T) {
	origRetryInterval := retryInterval
	defer func() { retryInterval = origRetryInterval }()
	retryInterval = 20 * time.Millisecond

	fileStorage := &certmagic.FileStorage{Path: t.TempDir()}
	mockStorage := &failingStorage{Storage: fileStorage}

	p := &Provider{
		storage: mockStorage,
		ctx:     caddy.Context{},
	}

	sts := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(30 * time.Millisecond),
		MaxKeys:          4,
	}

	initialKeys, err := p.Initialize(sts)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) != 1 {
		t.Fatalf("Expected 1 initial key, got %d", len(initialKeys))
	}

	// Induce transient load failure on next rotation tick
	mockStorage.mu.Lock()
	mockStorage.failLoad = true
	mockStorage.mu.Unlock()

	doneChan := make(chan struct{})
	keysChan := p.Next(doneChan)

	// Wait for rotation tick to attempt load and fail, resetting timer
	time.Sleep(50 * time.Millisecond)

	// Clear storage failure so retry tick succeeds
	mockStorage.mu.Lock()
	mockStorage.failLoad = false
	mockStorage.mu.Unlock()

	select {
	case updatedKeys := <-keysChan:
		if len(updatedKeys) < 1 {
			t.Errorf("Expected updated keys on retry, got %v", updatedKeys)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for distributed STEK rotation retry to succeed")
	}

	close(doneChan)
}
