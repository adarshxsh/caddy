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
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type customRandReader struct {
	mu       sync.Mutex
	realRand io.Reader
	fail     bool
}

func (c *customRandReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return 0, fmt.Errorf("simulated random source error")
	}
	return c.realRand.Read(p)
}

func (c *customRandReader) setFail(fail bool) {
	c.mu.Lock()
	c.fail = fail
	c.mu.Unlock()
}

func TestStandardSTEKRotationRetry(t *testing.T) {
	origRetryInterval := retryInterval
	defer func() { retryInterval = origRetryInterval }()
	retryInterval = 20 * time.Millisecond

	crr := &customRandReader{
		realRand: rand.Reader,
		fail:     false,
	}

	origRand := rand.Reader
	rand.Reader = crr

	sts := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(30 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initialKeys, err := provider.Initialize(sts)
	if err != nil {
		rand.Reader = origRand
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) != 1 {
		rand.Reader = origRand
		t.Fatalf("Expected 1 initial key, got %d", len(initialKeys))
	}

	// Fail next key generation attempt
	crr.setFail(true)

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	// Wait for timer to fire and fail key generation, triggering timer reset
	time.Sleep(50 * time.Millisecond)

	// Restore rand behavior so the retry tick succeeds
	crr.setFail(false)

	select {
	case updatedKeys := <-keysChan:
		if len(updatedKeys) < 1 {
			t.Errorf("Expected updated keys on retry, got %v", updatedKeys)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for standard STEK rotation retry to succeed")
	}

	close(doneChan)

	// Ensure background goroutine has stopped before restoring global rand.Reader
	time.Sleep(20 * time.Millisecond)
	rand.Reader = origRand
}
