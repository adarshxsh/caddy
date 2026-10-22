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
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated entropy failure")
}

type atomicReader struct {
	mu     sync.RWMutex
	reader io.Reader
}

func (a *atomicReader) Read(p []byte) (int, error) {
	a.mu.RLock()
	r := a.reader
	a.mu.RUnlock()
	return r.Read(p)
}

func (a *atomicReader) set(r io.Reader) {
	a.mu.Lock()
	a.reader = r
	a.mu.Unlock()
}

func TestCalculateBackoff(t *testing.T) {
	itvl := 24 * time.Hour
	tests := []struct {
		failures int
		expected time.Duration
	}{
		{0, itvl},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{100, itvl},
	}

	for _, tc := range tests {
		got := calculateBackoff(tc.failures, itvl)
		if got != tc.expected {
			t.Errorf("calculateBackoff(%d, %v) = %v; want %v", tc.failures, itvl, got, tc.expected)
		}
	}

	shortItvl := 10 * time.Second
	gotShort := calculateBackoff(1, shortItvl)
	if gotShort != shortItvl {
		t.Errorf("calculateBackoff(1, %v) = %v; want %v", shortItvl, gotShort, shortItvl)
	}
}

func TestStandardSTEKProvider_RotateRecovery(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(50 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected initial keys")
	}

	doneChan := make(chan struct{})
	defer close(doneChan)

	// Inject error into rand.Reader
	origReader := rand.Reader
	ar := &atomicReader{reader: errReader{}}
	rand.Reader = ar
	defer func() { rand.Reader = origReader }()

	keysChan := provider.Next(doneChan)

	// Wait briefly while error reader causes RotateSTEKs errors
	time.Sleep(120 * time.Millisecond)

	// Restore normal rand.Reader to simulate recovery from transient error
	ar.set(origReader)

	select {
	case keys := <-keysChan:
		if len(keys) == 0 {
			t.Errorf("expected non-empty keys after recovery")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("timed out waiting for key rotation recovery after error")
	}
}
