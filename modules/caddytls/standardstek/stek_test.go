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

func TestConcurrentRotation(t *testing.T) {
	mutex.Lock()
	keys = nil
	lastRotation = time.Time{}
	mutex.Unlock()

	stekConfig := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(5 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := standardSTEKProvider{}
	initialKeys, err := provider.Initialize(stekConfig)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) != 1 {
		t.Fatalf("expected 1 initial key, got %d", len(initialKeys))
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup

	// Goroutines concurrently reading global keys under RLock
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stop := time.After(100 * time.Millisecond)
			for {
				select {
				case <-stop:
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

	// Goroutine receiving keys from channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-doneChan:
				return
			case k, ok := <-keysChan:
				if !ok {
					return
				}
				_ = k
			}
		}
	}()

	time.Sleep(120 * time.Millisecond)
	close(doneChan)
	wg.Wait()
}
