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
	"crypto/tls"
	"sync"
	"testing"
)

type mockSTEKProvider struct{}

func (m *mockSTEKProvider) Initialize(s *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	ch := make(chan [][32]byte)
	go func() {
		<-doneChan
	}()
	return ch
}

func TestSessionTicketServiceStopUnstarted(t *testing.T) {
	s := &SessionTicketService{
		mu: new(sync.Mutex),
	}
	// Calling stop on an unstarted service should not panic
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil, got %v", s.stopChan)
	}

	// Unprovisioned service (nil mu) should also not panic
	sUnprovisioned := &SessionTicketService{}
	sUnprovisioned.stop()
}

func TestSessionTicketServiceStopSequential(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		configs:   make(map[*tls.Config]struct{}),
		mu:        new(sync.Mutex),
	}

	if err := s.start(); err != nil {
		t.Fatalf("failed to start session ticket service: %v", err)
	}

	// First stop call closes channel and sets stopChan to nil
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil after stop, got %v", s.stopChan)
	}

	// Subsequent stop calls should be no-ops and not panic
	s.stop()
	s.stop()
}

func TestSessionTicketServiceStopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	if err := s.start(); err != nil {
		t.Fatalf("failed to start session ticket service: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
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

func TestSessionTicketServiceStartStopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	var wg sync.WaitGroup
	const goroutines = 20

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = s.start()
		}()
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}

	wg.Wait()

	// Ensure cleanup
	s.stop()

	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil after final stop, got %v", s.stopChan)
	}
}
