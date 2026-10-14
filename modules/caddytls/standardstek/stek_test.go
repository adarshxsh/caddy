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
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type testRandReader struct {
	orig io.Reader
	fail atomic.Bool
}

func (r *testRandReader) Read(p []byte) (n int, err error) {
	if r.fail.Load() {
		return 0, errors.New("simulated crypto error")
	}
	return r.orig.Read(p)
}

func TestStandardSTEKTimerResetOnTransientError(t *testing.T) {
	origRand := rand.Reader
	tr := &testRandReader{orig: origRand}
	rand.Reader = tr
	defer func() {
		rand.Reader = origRand
	}()

	provider := &standardSTEKProvider{}
	cfg := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(20 * time.Millisecond),
		MaxKeys:          4,
	}

	// Initialize with normal rand reader behavior
	initialKeys, err := provider.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatalf("expected initial keys")
	}

	// Fail subsequent crypto reads to simulate transient error during tick
	tr.fail.Store(true)

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := provider.Next(doneChan)

	// Wait past one or more tick intervals while error persists
	time.Sleep(60 * time.Millisecond)

	// Verify no updated keys were emitted while in error state
	select {
	case k := <-keysChan:
		t.Fatalf("expected no keys during transient error, got: %v", k)
	default:
	}

	// Recover from transient error
	tr.fail.Store(false)

	// Verify that the timer loop resumed and successfully emitted updated keys on next tick
	select {
	case updatedKeys := <-keysChan:
		if len(updatedKeys) == 0 {
			t.Fatalf("expected updated keys after recovery, got empty")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for STEK rotation loop to recover after transient error")
	}
}
