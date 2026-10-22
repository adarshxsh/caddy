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

func TestStandardSTEK_ConcurrentRotation(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected initial keys, got 0")
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup

	// Consumer goroutine: reads rotated keys from keysChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case newKeys, ok := <-keysChan:
				if !ok {
					return
				}
				// Verify keys can be read safely
				_ = len(newKeys)
				for _, k := range newKeys {
					_ = k[0]
				}
			case <-doneChan:
				return
			}
		}
	}()

	// Reader goroutines: concurrently access package-level keys under RLock or read slice elements
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopTimer := time.After(150 * time.Millisecond)
			for {
				select {
				case <-stopTimer:
					return
				default:
					mutex.RLock()
					localKeys := keys
					mutex.RUnlock()

					// Read elements of localKeys slice to test for data races on element mutation
					for _, k := range localKeys {
						_ = k[0]
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(doneChan)
	wg.Wait()
}
