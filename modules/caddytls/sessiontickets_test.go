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
	"testing"
)

func TestRotateSTEKs_ImmutabilityAndBehavior(t *testing.T) {
	service := SessionTicketService{MaxKeys: 4}

	// Case 1: Empty input keys
	t.Run("Empty input keys", func(t *testing.T) {
		var initialKeys [][32]byte
		rotated, err := service.RotateSTEKs(initialKeys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rotated) != 1 {
			t.Fatalf("expected 1 key, got %d", len(rotated))
		}
	})

	// Case 2: Rotation under MaxKeys, verify input slice elements are not mutated
	t.Run("Under MaxKeys immutability", func(t *testing.T) {
		k1 := [32]byte{1, 1, 1}
		k2 := [32]byte{2, 2, 2}
		k3 := [32]byte{3, 3, 3}

		originalInput := [][32]byte{k1, k2, k3}
		inputSnapshot := [][32]byte{k1, k2, k3}

		rotated, err := service.RotateSTEKs(originalInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify output length
		if len(rotated) != 4 {
			t.Fatalf("expected 4 keys, got %d", len(rotated))
		}

		// Verify prepended new key and preserved order
		if !bytes.Equal(rotated[1][:], k1[:]) || !bytes.Equal(rotated[2][:], k2[:]) || !bytes.Equal(rotated[3][:], k3[:]) {
			t.Fatalf("rotated keys order incorrect")
		}

		// Verify input slice was NOT mutated in place
		for i := range originalInput {
			if !bytes.Equal(originalInput[i][:], inputSnapshot[i][:]) {
				t.Fatalf("originalInput[%d] was mutated! expected %v, got %v", i, inputSnapshot[i], originalInput[i])
			}
		}
	})

	// Case 3: Rotation at MaxKeys, verify oldest key elided and input slice unmodified
	t.Run("At MaxKeys elision and immutability", func(t *testing.T) {
		k1 := [32]byte{1}
		k2 := [32]byte{2}
		k3 := [32]byte{3}
		k4 := [32]byte{4}

		originalInput := [][32]byte{k1, k2, k3, k4}
		inputSnapshot := [][32]byte{k1, k2, k3, k4}

		rotated, err := service.RotateSTEKs(originalInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rotated) != 4 {
			t.Fatalf("expected 4 keys, got %d", len(rotated))
		}

		// Oldest key k4 should be elided in returned slice
		if !bytes.Equal(rotated[1][:], k1[:]) || !bytes.Equal(rotated[2][:], k2[:]) || !bytes.Equal(rotated[3][:], k3[:]) {
			t.Fatalf("rotated keys order incorrect")
		}

		// Verify input slice was NOT mutated in place
		for i := range originalInput {
			if !bytes.Equal(originalInput[i][:], inputSnapshot[i][:]) {
				t.Fatalf("originalInput[%d] was mutated! expected %v, got %v", i, inputSnapshot[i], originalInput[i])
			}
		}
	})

	// Case 4: Default MaxKeys fallback when MaxKeys <= 0
	t.Run("Default MaxKeys fallback", func(t *testing.T) {
		zeroService := SessionTicketService{MaxKeys: 0}
		k1 := [32]byte{1}
		k2 := [32]byte{2}
		k3 := [32]byte{3}
		k4 := [32]byte{4}

		rotated, err := zeroService.RotateSTEKs([][32]byte{k1, k2, k3, k4})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rotated) != defaultMaxSTEKs {
			t.Fatalf("expected %d keys with default MaxKeys, got %d", defaultMaxSTEKs, len(rotated))
		}
	})

	// Case 5: MaxKeys = 1
	t.Run("MaxKeys = 1", func(t *testing.T) {
		singleService := SessionTicketService{MaxKeys: 1}
		k1 := [32]byte{1}
		k2 := [32]byte{2}

		rotated, err := singleService.RotateSTEKs([][32]byte{k1, k2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rotated) != 1 {
			t.Fatalf("expected 1 key, got %d", len(rotated))
		}
	})
}
