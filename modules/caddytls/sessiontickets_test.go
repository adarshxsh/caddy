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
	"sync"
	"testing"
	"time"
)

type mockSTEKProvider struct {
	nextCalled chan struct{}
}

func (m *mockSTEKProvider) Initialize(s *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	if m.nextCalled != nil {
		close(m.nextCalled)
	}
	ch := make(chan [][32]byte)
	return ch
}

func TestSessionTicketService_StopSequential(t *testing.T) {
	s := &SessionTicketService{
		stopChan:  make(chan struct{}),
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	// Multiple sequential calls to stop should not panic and clear stopChan
	for i := 0; i < 5; i++ {
		s.stop()
		if s.stopChan != nil {
			t.Errorf("iteration %d: expected stopChan to be nil after stop(), got %v", i, s.stopChan)
		}
	}
}

func TestSessionTicketService_StopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		stopChan:  make(chan struct{}),
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}

	wg.Wait()

	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil after concurrent stop calls, got %v", s.stopChan)
	}
}

func TestSessionTicketService_StopUnstarted(t *testing.T) {
	s := &SessionTicketService{
		mu: new(sync.Mutex),
	}

	// Calling stop on an unstarted service (stopChan == nil) should not panic
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected stopChan to remain nil, got %v", s.stopChan)
	}
}

func TestSessionTicketService_StartAndStop(t *testing.T) {
	nextCalled := make(chan struct{})
	mock := &mockSTEKProvider{nextCalled: nextCalled}

	s := &SessionTicketService{
		keySource: mock,
		mu:        new(sync.Mutex),
	}

	if err := s.start(); err != nil {
		t.Fatalf("unexpected error starting SessionTicketService: %v", err)
	}

	select {
	case <-nextCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stayUpdated to invoke Next()")
	}

	// Stop multiple times sequentially and concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}
	wg.Wait()

	s.stop()

	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil, got %v", s.stopChan)
	}
}
