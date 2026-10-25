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

func TestStandardSTEKProvider_RotateRace(t *testing.T) {
	// Reset package global variables for the test
	mutex.Lock()
	keys = nil
	lastRotation = time.Time{}
	mutex.Unlock()

	sts := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(1 * time.Millisecond),
		MaxKeys:          2,
	}

	provider := &standardSTEKProvider{}
	initialKeys, err := provider.Initialize(sts)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatalf("expected initial keys, got empty")
	}

	done := make(chan struct{})
	keysChan := provider.Next(done)

	var wg sync.WaitGroup

	// Goroutine reading global keys slice under read lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		stopTime := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(stopTime) {
			mutex.RLock()
			for _, k := range keys {
				_ = k[0]
			}
			mutex.RUnlock()
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Goroutine reading received keys from keysChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		stopTime := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(stopTime) {
			select {
			case k, ok := <-keysChan:
				if !ok {
					return
				}
				for _, key := range k {
					_ = key[0]
				}
			default:
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	wg.Wait()
	close(done)
}
