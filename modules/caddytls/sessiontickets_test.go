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

func (m *mockSTEKProvider) Initialize(s *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	m.keysChan = make(chan [][32]byte)
	go func() {
		<-doneChan
		close(m.keysChan)
	}()
	return m.keysChan
}

func TestSessionTicketServiceStop(t *testing.T) {
	// Test stopping an uninitialized service (s.stopChan == nil)
	uninitService := &SessionTicketService{}
	uninitService.stop() // Should not panic

	// Test sequential stop calls after start
	service := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	err := service.start()
	if err != nil {
		t.Fatalf("unexpected error starting SessionTicketService: %v", err)
	}

	// First stop call
	service.stop()

	// Subsequent stop calls should not panic
	service.stop()
	service.stop()

	// Test concurrent stop calls after start
	concurrentService := &SessionTicketService{
		keySource: &mockSTEKProvider{},
		mu:        new(sync.Mutex),
	}

	err = concurrentService.start()
	if err != nil {
		t.Fatalf("unexpected error starting SessionTicketService: %v", err)
	}

	var wg sync.WaitGroup
	const numGoroutines = 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrentService.stop()
		}()
	}
	wg.Wait()
}
