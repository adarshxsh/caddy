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
	return [][32]byte{{1, 2, 3, 4}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	m.keysChan = make(chan [][32]byte)
	go func() {
		<-doneChan
	}()
	return m.keysChan
}

func TestSessionTicketServiceStopUninitialized(t *testing.T) {
	s := &SessionTicketService{}
	// calling stop when stopChan is nil should not panic
	s.stop()
	s.stop()
}

func TestSessionTicketServiceStopRepeated(t *testing.T) {
	s := &SessionTicketService{
		stopChan: make(chan struct{}),
	}

	// Call stop multiple times
	for i := 0; i < 5; i++ {
		s.stop()
	}

	// Verify channel is closed
	select {
	case <-s.stopChan:
		// expected: channel is closed
	default:
		t.Errorf("expected stopChan to be closed")
	}
}

func TestSessionTicketServiceStopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		stopChan: make(chan struct{}),
	}

	var wg sync.WaitGroup
	const goroutines = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}

	wg.Wait()

	select {
	case <-s.stopChan:
		// expected: channel is closed
	default:
		t.Errorf("expected stopChan to be closed")
	}
}

func TestSessionTicketServiceStopWithStart(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	if err := s.start(); err != nil {
		t.Fatalf("unexpected error starting SessionTicketService: %v", err)
	}

	// Call stop multiple times after start
	s.stop()
	s.stop()

	select {
	case <-s.stopChan:
		// expected: channel is closed
	default:
		t.Errorf("expected stopChan to be closed")
	}
}
