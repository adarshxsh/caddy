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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("entropy failure")
}

func TestStandardSTEKRotationBackoff(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	keys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("expected initial keys, got empty")
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	// Inject error into key generation
	service.SetRandReaderForTest(errReader{})

	// Wait for a backoff cycle on failure
	time.Sleep(30 * time.Millisecond)

	if atomic.LoadInt32(&provider.numFailures) == 0 {
		t.Errorf("expected numFailures > 0 after key generation error")
	}

	// Clear error and restore normal RNG
	service.SetRandReaderForTest(nil)

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("expected updated keys after recovery, got empty")
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("timeout waiting for updated keys after recovery")
	}

	if nf := atomic.LoadInt32(&provider.numFailures); nf != 0 {
		t.Errorf("expected numFailures reset to 0 after success, got %d", nf)
	}

	close(doneChan)
}
