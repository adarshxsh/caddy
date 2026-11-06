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

func TestRotateSTEKsNoInPlaceMutation(t *testing.T) {
	stekService := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(time.Hour),
		MaxKeys:          4,
	}

	key1 := [32]byte{1, 1, 1}
	key2 := [32]byte{2, 2, 2}
	key3 := [32]byte{3, 3, 3}
	key4 := [32]byte{4, 4, 4}

	orig := [][32]byte{key1, key2, key3, key4}
	origCopy := make([][32]byte, len(orig))
	copy(origCopy, orig)

	newKeys, err := stekService.RotateSTEKs(orig)
	if err != nil {
		t.Fatalf("unexpected error from RotateSTEKs: %v", err)
	}

	// Verify original slice elements were not mutated in place
	if len(orig) != len(origCopy) {
		t.Fatalf("original slice length changed: got %d, want %d", len(orig), len(origCopy))
	}
	for i := range orig {
		if !bytes.Equal(orig[i][:], origCopy[i][:]) {
			t.Errorf("original slice element %d mutated: got %v, want %v", i, orig[i], origCopy[i])
		}
	}

	// Verify new keys slice contents
	if len(newKeys) != 4 {
		t.Fatalf("expected 4 keys in rotated slice, got %d", len(newKeys))
	}
	if !bytes.Equal(newKeys[1][:], key1[:]) || !bytes.Equal(newKeys[2][:], key2[:]) || !bytes.Equal(newKeys[3][:], key3[:]) {
		t.Errorf("rotated keys unexpected content: %v", newKeys)
	}
}

func TestSTEKRotationLimits(t *testing.T) {
	stekService := &caddytls.SessionTicketService{
		MaxKeys: 2,
	}

	k1 := [32]byte{1}
	k2 := [32]byte{2}
	keys := [][32]byte{k1, k2}

	newKeys, err := stekService.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("RotateSTEKs error: %v", err)
	}
	if len(newKeys) != 2 {
		t.Fatalf("expected max 2 keys, got %d", len(newKeys))
	}
	if !bytes.Equal(newKeys[1][:], k1[:]) {
		t.Errorf("expected k1 at index 1, got %v", newKeys[1])
	}
}

func TestSTEKRotationRace(t *testing.T) {
	stekService := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(time.Millisecond * 2),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initialKeys, err := provider.Initialize(stekService)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatal("expected non-empty initial keys")
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup
	activeKeys := initialKeys
	var activeMu sync.RWMutex

	// Goroutine reading rotated keys from channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case keys, ok := <-keysChan:
				if !ok {
					return
				}
				activeMu.Lock()
				activeKeys = keys
				activeMu.Unlock()
			case <-doneChan:
				return
			}
		}
	}()

	// Concurrent reader goroutines simulating active TLS handshakes reading keys
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopTimer := time.After(time.Millisecond * 100)
			for {
				select {
				case <-stopTimer:
					return
				default:
					activeMu.RLock()
					ks := activeKeys
					for _, k := range ks {
						_ = k[0]
						_ = k[31]
					}
					activeMu.RUnlock()
					time.Sleep(time.Microsecond * 100)
				}
			}
		}()
	}

	time.Sleep(time.Millisecond * 100)
	close(doneChan)
	wg.Wait()
}
