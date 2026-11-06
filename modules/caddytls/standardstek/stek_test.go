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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated crypto rand error")
}

func TestStandardSTEK_RotationRetryOnError(t *testing.T) {
	provider := &standardSTEKProvider{}
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(100 * time.Millisecond),
		MaxKeys:          4,
	}

	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("Expected initial keys, got none")
	}

	// Temporarily simulate key generation error by injecting errReader into rand.Reader
	origReader := rand.Reader
	rand.Reader = errReader{}

	doneChan := make(chan struct{})
	defer close(doneChan)

	keysChan := provider.Next(doneChan)

	// Restore rand.Reader shortly after rotation trigger so retry succeeds
	go func() {
		time.Sleep(150 * time.Millisecond)
		rand.Reader = origReader
	}()
	defer func() {
		rand.Reader = origReader
	}()

	select {
	case newKeys := <-keysChan:
		if len(newKeys) == 0 {
			t.Errorf("Received empty keys after rotation retry")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for standard STEK rotation retry after simulated error")
	}
}
