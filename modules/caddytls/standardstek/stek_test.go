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

type errorRandReader struct {
	mu        sync.Mutex
	failReads int
	underlying io.Reader
}

func (r *errorRandReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failReads > 0 {
		r.failReads--
		return 0, fmt.Errorf("simulated rand reader failure")
	}
	return r.underlying.Read(p)
}

func TestStandardSTEK_TimerResetOnErrorAndShutdown(t *testing.T) {
	origRand := rand.Reader
	errReader := &errorRandReader{
		failReads:  0,
		underlying: origRand,
	}

	rand.Reader = errReader
	defer func() {
		rand.Reader = origRand
	}()

	svc := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(20 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initialKeys, err := provider.Initialize(svc)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initialKeys) == 0 {
		t.Fatalf("expected initial keys, got empty slice")
	}

	// Cause the next rand.Read (in rotate loop's first tick) to fail
	errReader.mu.Lock()
	errReader.failReads = 1
	errReader.mu.Unlock()

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	// The first timer tick will fail because failReads = 1.
	// With deferred timer reset, the loop will reset the timer and retry.
	// The second timer tick will succeed.
	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Errorf("received empty keys on successful rotation")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for key rotation after transient error; timer reset on error likely failed")
	}

	// Clean shutdown test on doneChan
	close(doneChan)

	// Ensure no goroutine panic or hang after closing doneChan
	time.Sleep(50 * time.Millisecond)
}
