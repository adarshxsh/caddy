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

package caddytls

import (
	"bytes"
	"sync"
	"testing"
)

func TestRotateSTEKsEdgeCasesAndImmutability(t *testing.T) {
	// Test MaxKeys = 0
	service := SessionTicketService{MaxKeys: 0}
	var k1 [32]byte
	k1[0] = 1
	keys := [][32]byte{k1}

	res, err := service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error with MaxKeys=0: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 keys with MaxKeys=0, got %d", len(res))
	}
	// Verify input slice was not mutated
	if keys[0][0] != 1 {
		t.Errorf("input slice was mutated: keys[0][0] = %d, expected 1", keys[0][0])
	}

	// Test MaxKeys = 1 with empty input
	service.MaxKeys = 1
	res, err = service.RotateSTEKs(nil)
	if err != nil {
		t.Fatalf("unexpected error with MaxKeys=1 and nil keys: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("expected 1 key with MaxKeys=1, got %d", len(res))
	}

	// Test MaxKeys = 1 with populated input
	res, err = service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error with MaxKeys=1: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("expected 1 key with MaxKeys=1, got %d", len(res))
	}
	if bytes.Equal(res[0][:], k1[:]) {
		t.Errorf("expected new key, but got the old key")
	}
	if keys[0][0] != 1 {
		t.Errorf("input slice was mutated: keys[0][0] = %d, expected 1", keys[0][0])
	}

	// Test MaxKeys = 4 filling up and eliding oldest
	service.MaxKeys = 4
	var current [][32]byte
	for i := 0; i < 5; i++ {
		origCopy := make([][32]byte, len(current))
		copy(origCopy, current)

		next, err := service.RotateSTEKs(current)
		if err != nil {
			t.Fatalf("unexpected error on rotation %d: %v", i, err)
		}

		// Verify input slice 'current' was not mutated
		if len(current) != len(origCopy) {
			t.Errorf("input slice length changed: got %d, expected %d", len(current), len(origCopy))
		}
		for j := range current {
			if !bytes.Equal(current[j][:], origCopy[j][:]) {
				t.Errorf("input slice element %d mutated", j)
			}
		}

		current = next
		expectedLen := i + 1
		if expectedLen > 4 {
			expectedLen = 4
		}
		if len(current) != expectedLen {
			t.Errorf("step %d: expected length %d, got %d", i, expectedLen, len(current))
		}
	}
}

func TestRotateSTEKsConcurrentReads(t *testing.T) {
	service := SessionTicketService{MaxKeys: 4}

	// Initial set of keys
	var k1, k2, k3, k4 [32]byte
	k1[0], k2[0], k3[0], k4[0] = 1, 2, 3, 4
	sharedKeys := [][32]byte{k1, k2, k3, k4}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Spawn concurrent readers reading sharedKeys
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					// Read all bytes in sharedKeys slice
					for _, key := range sharedKeys {
						_ = key[0]
					}
				}
			}
		}()
	}

	// Concurrently call RotateSTEKs on sharedKeys
	for i := 0; i < 50; i++ {
		_, err := service.RotateSTEKs(sharedKeys)
		if err != nil {
			t.Fatalf("RotateSTEKs error: %v", err)
		}
	}

	close(stopChan)
	wg.Wait()
}
