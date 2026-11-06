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
	"testing"
	"time"
)

func TestCalculateSTEKBackoff(t *testing.T) {
	interval := 12 * time.Hour

	// Test consecutive failure scaling
	b1 := CalculateSTEKBackoff(1, interval)
	b2 := CalculateSTEKBackoff(2, interval)
	b3 := CalculateSTEKBackoff(3, interval)

	if b1 < 10*time.Second || b1 > 12*time.Second {
		t.Errorf("expected b1 around 10s, got %v", b1)
	}

	if b2 < 20*time.Second || b2 > 24*time.Second {
		t.Errorf("expected b2 around 20s, got %v", b2)
	}

	if b3 < 40*time.Second || b3 > 48*time.Second {
		t.Errorf("expected b3 around 40s, got %v", b3)
	}

	// Test max backoff ceiling cap (1 hour)
	b100 := CalculateSTEKBackoff(100, interval)
	if b100 > 1*time.Hour {
		t.Errorf("expected backoff capped at 1h, got %v", b100)
	}

	// Test small rotation interval clamping
	smallInterval := 100 * time.Millisecond
	sb1 := CalculateSTEKBackoff(1, smallInterval)
	if sb1 > smallInterval {
		t.Errorf("expected backoff capped at rotation interval %v, got %v", smallInterval, sb1)
	}

	// Test non-positive failure counts
	bZero := CalculateSTEKBackoff(0, interval)
	if bZero < 10*time.Second || bZero > 12*time.Second {
		t.Errorf("expected failure count 0 to be treated as 1, got %v", bZero)
	}
}
