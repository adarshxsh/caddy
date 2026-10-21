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

type failingStorage struct {
	certmagic.Storage
	mu        sync.Mutex
	failLoad  bool
	loadCount int
}

func (f *failingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadCount++
	if f.failLoad && f.loadCount == 2 {
		return nil, errors.New("simulated storage failure")
	}
	return f.Storage.Load(ctx, key)
}

func TestDistributedSTEK_RotationRetryOnError(t *testing.T) {
	dir := t.TempDir()
	baseStorage := &certmagic.FileStorage{Path: dir}
	mockStorage := &failingStorage{
		Storage:  baseStorage,
		failLoad: true,
	}

	provider := &Provider{
		storage: mockStorage,
		ctx:     caddy.Context{},
	}

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(100 * time.Millisecond),
		MaxKeys:          4,
	}

	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("Expected initial keys, got none")
	}

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := provider.Next(doneChan)

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("Received empty keys after rotation retry")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for STEK rotation retry after simulated error")
	}
}
