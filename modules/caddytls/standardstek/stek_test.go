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

package standardstek

import (
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestSTEKRotation_Race(t *testing.T) {
	mutex.Lock()
	lastRotation = time.Time{}
	keys = nil
	mutex.Unlock()

	config := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          3,
	}

	provider := &standardSTEKProvider{}
	initKeys, err := provider.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected initial keys, got empty")
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup
	stopReaders := make(chan struct{})

	// Start concurrent reader goroutines that read global keys under RLock
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					mutex.RLock()
					for _, k := range keys {
						_ = k[0]
					}
					mutex.RUnlock()
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Receive multiple key rotations
	for i := 0; i < 5; i++ {
		select {
		case rotatedKeys := <-keysChan:
			if len(rotatedKeys) == 0 {
				t.Errorf("received empty rotated keys")
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for key rotation iteration %d", i)
		}
	}

	close(stopReaders)
	wg.Wait()
	close(doneChan)
}
