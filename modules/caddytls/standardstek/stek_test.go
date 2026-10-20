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
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestStandardSTEKRotation(t *testing.T) {
	// Reset package global state for test isolation
	mutex.Lock()
	keys = nil
	lastRotation = time.Time{}
	mutex.Unlock()

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(20 * time.Millisecond),
		MaxKeys:          3,
	}

	provider := &standardSTEKProvider{}
	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if len(initKeys) != 1 {
		t.Fatalf("expected 1 initial key, got %d", len(initKeys))
	}

	// Keep a copy of the initial key array content
	initialKeyVal := initKeys[0]

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	// Launch concurrent readers reading initial keys and global keys
	stopReaders := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
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

					// also inspect the caller's slice memory
					_ = initKeys[0][0]
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Wait for multiple rotation ticks
	var rot1, rot2 [][32]byte
	select {
	case rot1 = <-keysChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for 1st key rotation")
	}

	select {
	case rot2 = <-keysChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for 2nd key rotation")
	}

	close(stopReaders)
	wg.Wait()
	close(doneChan)

	// Verify that initial key value is still preserved and not corrupted
	if !bytes.Equal(initKeys[0][:], initialKeyVal[:]) {
		t.Fatalf("initial key backing memory was mutated!")
	}

	if len(rot1) != 2 {
		t.Errorf("expected rot1 to have 2 keys, got %d", len(rot1))
	}

	if len(rot2) != 3 {
		t.Errorf("expected rot2 to have 3 keys, got %d", len(rot2))
	}
}

func TestStandardSTEKInitializeFresh(t *testing.T) {
	mutex.Lock()
	keys = nil
	lastRotation = time.Now()
	mutex.Unlock()

	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Minute),
		MaxKeys:          4,
	}

	// Manually inject a key
	mutex.Lock()
	var sampleKey [32]byte
	sampleKey[0] = 0x42
	keys = [][32]byte{sampleKey}
	mutex.Unlock()

	provider := &standardSTEKProvider{}
	returnedKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize error: %v", err)
	}

	if len(returnedKeys) != 1 || returnedKeys[0][0] != 0x42 {
		t.Fatalf("expected preserved fresh keys, got %v", returnedKeys)
	}

	// Stop timer created by Initialize
	if provider.timer != nil {
		provider.timer.Stop()
	}
}
