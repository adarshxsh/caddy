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

type dummySTEKProvider struct {
	keysChan chan [][32]byte
}

func (d *dummySTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3}}, nil
}

func (d *dummySTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	d.keysChan = make(chan [][32]byte)
	go func() {
		<-doneChan
	}()
	return d.keysChan
}

func TestSessionTicketService_StopSequential(t *testing.T) {
	s := &SessionTicketService{
		keySource: &dummySTEKProvider{},
		configs:   make(map[*tls.Config]struct{}),
		mu:        new(sync.Mutex),
	}

	err := s.start()
	if err != nil {
		t.Fatalf("unexpected error on start: %v", err)
	}

	// First stop call should close stopChan and set it to nil
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil after stop(), got %v", s.stopChan)
	}

	// Subsequent stop calls should be safe no-ops and not panic
	s.stop()
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected stopChan to remain nil after repeated stop(), got %v", s.stopChan)
	}
}

func TestSessionTicketService_StopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		keySource: &dummySTEKProvider{},
		configs:   make(map[*tls.Config]struct{}),
		mu:        new(sync.Mutex),
	}

	err := s.start()
	if err != nil {
		t.Fatalf("unexpected error on start: %v", err)
	}

	const numGoroutines = 20
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
		t.Errorf("expected stopChan to be nil after concurrent stop(), got %v", s.stopChan)
	}
}

func TestSessionTicketService_StartStopRace(t *testing.T) {
	s := &SessionTicketService{
		keySource: &dummySTEKProvider{},
		configs:   make(map[*tls.Config]struct{}),
		mu:        new(sync.Mutex),
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
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
	// Cleanup at the end
	s.stop()

	if s.stopChan != nil {
		t.Errorf("expected stopChan to be nil after final stop(), got %v", s.stopChan)
	}
}
