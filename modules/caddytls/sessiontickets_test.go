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
)

type mockSTEKProvider struct {
	keysChan chan [][32]byte
}

func (m *mockSTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	m.keysChan = make(chan [][32]byte)
	return [][32]byte{{1, 2, 3}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	go func() {
		<-doneChan
		close(m.keysChan)
	}()
	return m.keysChan
}

func TestSessionTicketService_StopIdempotent(t *testing.T) {
	mock := &mockSTEKProvider{}
	service := &SessionTicketService{
		keySource: mock,
	}

	err := service.start()
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	// Calling stop multiple times sequentially should not panic or error
	for i := 0; i < 5; i++ {
		service.stop()
	}

	if service.stopChan != nil {
		t.Errorf("expected stopChan to be nil after stop(), got %v", service.stopChan)
	}
}

func TestSessionTicketService_StopConcurrent(t *testing.T) {
	mock := &mockSTEKProvider{}
	service := &SessionTicketService{
		keySource: mock,
	}

	err := service.start()
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	var wg sync.WaitGroup
	const numGoroutines = 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			service.stop()
		}()
	}

	wg.Wait()

	if service.stopChan != nil {
		t.Errorf("expected stopChan to be nil after concurrent stop(), got %v", service.stopChan)
	}
}

func TestSessionTicketService_StopUnprovisioned(t *testing.T) {
	// Service created directly without calling provision() or start()
	service := &SessionTicketService{}

	// Calling stop on unprovisioned service should initialize mu safely and not panic
	service.stop()

	if service.mu == nil {
		t.Errorf("expected mu to be initialized after stop(), got nil")
	}

	// Calling stop again should remain safe
	service.stop()
}

func TestSessionTicketService_StartStopCycle(t *testing.T) {
	mock := &mockSTEKProvider{}
	service := &SessionTicketService{
		keySource: mock,
	}

	// First cycle
	err := service.start()
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	service.stop()

	// Second cycle
	err = service.start()
	if err != nil {
		t.Fatalf("unexpected restart error: %v", err)
	}
	service.stop()
}
