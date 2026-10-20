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

func TestRotateSTEKs(t *testing.T) {
	service := SessionTicketService{MaxKeys: 3}

	var keys [][32]byte
	var err error

	// First key
	keys, err = service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	k1 := keys[0]

	// Second key
	keys, err = service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	k2 := keys[0]
	if !bytes.Equal(keys[1][:], k1[:]) {
		t.Errorf("expected k1 at index 1")
	}

	// Third key (reaches MaxKeys)
	keys, err = service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	k3 := keys[0]
	if !bytes.Equal(keys[1][:], k2[:]) || !bytes.Equal(keys[2][:], k1[:]) {
		t.Errorf("expected k2 at index 1 and k1 at index 2")
	}

	// Fourth key (exceeds MaxKeys, k1 should be dropped)
	keys, err = service.RotateSTEKs(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected MaxKeys limit of 3, got %d", len(keys))
	}
	if !bytes.Equal(keys[1][:], k3[:]) || !bytes.Equal(keys[2][:], k2[:]) {
		t.Errorf("expected k3 at index 1 and k2 at index 2")
	}

	// Verify input slice immutability
	inputKeys := [][32]byte{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}
	inputCopy := make([][32]byte, len(inputKeys))
	copy(inputCopy, inputKeys)

	_, err = service.RotateSTEKs(inputKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := range inputKeys {
		if !bytes.Equal(inputKeys[i][:], inputCopy[i][:]) {
			t.Errorf("input slice element %d was mutated in place", i)
		}
	}
}

func TestRotateSTEKs_Race(t *testing.T) {
	service := SessionTicketService{MaxKeys: 4}

	initialKeys := [][32]byte{
		{1, 1, 1},
		{2, 2, 2},
		{3, 3, 3},
		{4, 4, 4},
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Readers reading from initialKeys
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 500; j++ {
				for _, k := range initialKeys {
					_ = k[0]
				}
			}
		}()
	}

	// Writers rotating STEKs using initialKeys as input
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				_, err := service.RotateSTEKs(initialKeys)
				if err != nil {
					t.Errorf("RotateSTEKs failed: %v", err)
				}
			}
		}()
	}

	close(start)
	wg.Wait()
}
