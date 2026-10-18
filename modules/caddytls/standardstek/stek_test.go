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

func TestStandardSTEK_SliceIndependence(t *testing.T) {
	mutex.Lock()
	keys = [][32]byte{{1}, {2}, {3}, {4}}
	lastRotation = time.Now()
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		lastRotation = time.Time{}
		keys = nil
		mutex.Unlock()
	}()

	mutex.RLock()
	keysCopy := append([][32]byte(nil), keys...)
	mutex.RUnlock()

	// Verify that modifying keysCopy does not affect global keys
	keysCopy[0][0] = 0xAA
	keysCopy[3][0] = 0xBB

	mutex.RLock()
	if keys[0][0] == 0xAA || keys[3][0] == 0xBB {
		t.Fatal("Global keys slice was mutated when keysCopy was modified - backing array was not independent!")
	}
	mutex.RUnlock()
}

func TestStandardSTEKRotation_DeepCopyAndRace(t *testing.T) {
	mutex.Lock()
	lastRotation = time.Time{}
	keys = nil
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		lastRotation = time.Time{}
		keys = nil
		mutex.Unlock()
	}()

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := new(standardSTEKProvider)

	initialKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if len(initialKeys) != 1 {
		t.Fatalf("Expected 1 initial key, got %d", len(initialKeys))
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup

	// Worker 1: Read keys from keysChan during rotation
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case newKeys, ok := <-keysChan:
				if !ok {
					return
				}
				if len(newKeys) == 0 {
					t.Errorf("Received empty keys from keysChan")
				}
			case <-doneChan:
				return
			}
		}
	}()

	// Workers 2-6: Concurrent readers accessing package-level `keys` under mutex.RLock()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stop := time.After(200 * time.Millisecond)
			for {
				select {
				case <-stop:
					return
				default:
					mutex.RLock()
					k := append([][32]byte(nil), keys...)
					mutex.RUnlock()
					if len(k) == 0 {
						t.Errorf("Expected non-empty keys slice during rotation")
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)

	close(doneChan)
	wg.Wait()

	mutex.RLock()
	finalKeys := append([][32]byte(nil), keys...)
	mutex.RUnlock()

	if len(finalKeys) == 0 {
		t.Fatal("Expected non-empty final keys after rotations")
	}
}

func TestStandardSTEKRotation_NilKeysCopy(t *testing.T) {
	mutex.Lock()
	keys = nil
	mutex.Unlock()

	mutex.RLock()
	keysCopy := append([][32]byte(nil), keys...)
	mutex.RUnlock()

	if keysCopy != nil && len(keysCopy) != 0 {
		t.Fatalf("Expected nil/empty slice copy when keys is nil, got len %d", len(keysCopy))
	}

	service := &caddytls.SessionTicketService{
		MaxKeys: 4,
	}

	rotated, err := service.RotateSTEKs(keysCopy)
	if err != nil {
		t.Fatalf("RotateSTEKs failed on empty slice: %v", err)
	}

	if len(rotated) != 1 {
		t.Fatalf("Expected 1 key after RotateSTEKs, got %d", len(rotated))
	}
}
