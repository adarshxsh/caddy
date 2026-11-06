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

type mockSTEKProvider struct {
	keysChan chan [][32]byte
}

func (m *mockSTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	return m.keysChan
}

func TestSessionTicketService_StopUnprovisioned(t *testing.T) {
	s := &SessionTicketService{}
	// stop on unprovisioned instance where s.mu is nil and s.stopChan is nil
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected s.stopChan to be nil, got %v", s.stopChan)
	}
}

func TestSessionTicketService_StopIdempotent(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{
			keysChan: make(chan [][32]byte),
		},
		configs: make(map[*tls.Config]struct{}),
	}
	err := s.start()
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	// first stop should close channel and set s.stopChan to nil
	s.stop()
	if s.stopChan != nil {
		t.Errorf("expected s.stopChan to be nil after stop, got %v", s.stopChan)
	}

	// subsequent stop calls should be no-ops
	s.stop()
	s.stop()
}

func TestSessionTicketService_StopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		keySource: &mockSTEKProvider{
			keysChan: make(chan [][32]byte),
		},
	}
	err := s.start()
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}
	wg.Wait()

	if s.stopChan != nil {
		t.Errorf("expected s.stopChan to be nil after concurrent stop, got %v", s.stopChan)
	}
}
