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

type atomicReader struct {
	mu     sync.Mutex
	fail   bool
	target io.Reader
}

func (a *atomicReader) setFail(fail bool) {
	a.mu.Lock()
	a.fail = fail
	a.mu.Unlock()
}

func (a *atomicReader) Read(p []byte) (int, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return 0, fmt.Errorf("simulated random source failure")
	}
	return a.target.Read(p)
}

func TestSTEKBackoffDelay(t *testing.T) {
	tests := []struct {
		failures int
		expected time.Duration
	}{
		{failures: -1, expected: 10 * time.Second},
		{failures: 0, expected: 10 * time.Second},
		{failures: 1, expected: 10 * time.Second},
		{failures: 2, expected: 20 * time.Second},
		{failures: 3, expected: 40 * time.Second},
		{failures: 4, expected: 80 * time.Second},
		{failures: 5, expected: 160 * time.Second},
		{failures: 6, expected: 300 * time.Second},
		{failures: 7, expected: 5 * time.Minute},
		{failures: 100, expected: 5 * time.Minute},
	}

	for _, tt := range tests {
		delay := stekBackoffDelay(tt.failures)
		if delay != tt.expected {
			t.Errorf("stekBackoffDelay(%d) = %v; want %v", tt.failures, delay, tt.expected)
		}
	}
}

func TestStandardSTEKHandleTick(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{
		stekConfig: service,
		timer:      time.NewTimer(100 * time.Millisecond),
	}

	keysChan := make(chan [][32]byte, 10)

	origReader := rand.Reader
	customReader := &atomicReader{
		fail:   true,
		target: origReader,
	}
	rand.Reader = customReader
	defer func() {
		rand.Reader = origReader
	}()

	// 1. First tick fails
	err := provider.handleTick(time.Now(), keysChan)
	if err == nil {
		t.Fatal("expected error on simulated failure, got nil")
	}

	provider.mu.Lock()
	numFailures := provider.numFailures
	provider.mu.Unlock()
	if numFailures != 1 {
		t.Fatalf("expected numFailures=1, got %d", numFailures)
	}

	// 2. Second tick fails
	err = provider.handleTick(time.Now(), keysChan)
	if err == nil {
		t.Fatal("expected error on simulated failure, got nil")
	}

	provider.mu.Lock()
	numFailures = provider.numFailures
	provider.mu.Unlock()
	if numFailures != 2 {
		t.Fatalf("expected numFailures=2, got %d", numFailures)
	}

	// 3. Recovery: clear failure state
	customReader.setFail(false)
	err = provider.handleTick(time.Now(), keysChan)
	if err != nil {
		t.Fatalf("expected success after recovery, got error: %v", err)
	}

	provider.mu.Lock()
	numFailures = provider.numFailures
	provider.mu.Unlock()
	if numFailures != 0 {
		t.Fatalf("expected numFailures=0 on recovery, got %d", numFailures)
	}

	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Fatal("expected non-empty keys slice on success")
		}
	default:
		t.Fatal("expected keys sent on keysChan after successful tick")
	}
}

func TestStandardSTEKRotationBackoffAndRecovery(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{
		stekConfig: service,
		timer:      time.NewTimer(5 * time.Millisecond),
	}

	doneChan := make(chan struct{})
	keysChan := make(chan [][32]byte, 10)

	origReader := rand.Reader
	customReader := &atomicReader{
		fail:   true,
		target: origReader,
	}
	rand.Reader = customReader

	defer func() {
		rand.Reader = origReader
	}()

	go provider.rotate(doneChan, keysChan)

	// Wait briefly for timer to trigger failure path
	time.Sleep(30 * time.Millisecond)

	select {
	case k := <-keysChan:
		t.Fatalf("expected no keys on error, received: %v", k)
	default:
	}

	// Restore normal operation
	customReader.setFail(false)

	// Reset timer to fire soon for recovery test
	provider.timer.Reset(5 * time.Millisecond)

	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Fatal("expected non-empty keys slice on recovery")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for keys after recovery")
	}

	close(doneChan)
}
