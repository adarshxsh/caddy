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

type dummySTEKProvider struct {
	keysChan chan [][32]byte
}

func (d *dummySTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	d.keysChan = make(chan [][32]byte)
	return [][32]byte{{1, 2, 3}}, nil
}

func (d *dummySTEKProvider) Next(doneChan <-chan struct{}) (keysChan <-chan [][32]byte) {
	return d.keysChan
}

func TestSessionTicketService_StopIdempotent(t *testing.T) {
	t.Run("stop before start", func(t *testing.T) {
		s := &SessionTicketService{}
		// s.stopChan is nil, calling stop should not panic
		s.stop()
	})

	t.Run("sequential stop calls", func(t *testing.T) {
		provider := &dummySTEKProvider{}
		s := &SessionTicketService{
			keySource: provider,
			mu:        new(sync.Mutex),
		}
		if err := s.start(); err != nil {
			t.Fatalf("unexpected start error: %v", err)
		}

		// Multiple sequential calls to stop()
		for i := 0; i < 5; i++ {
			s.stop()
		}

		select {
		case <-s.stopChan:
			// Expected: channel is closed
		default:
			t.Fatal("stopChan was not closed")
		}
	})

	t.Run("concurrent stop calls", func(t *testing.T) {
		provider := &dummySTEKProvider{}
		s := &SessionTicketService{
			keySource: provider,
			mu:        new(sync.Mutex),
		}
		if err := s.start(); err != nil {
			t.Fatalf("unexpected start error: %v", err)
		}

		var wg sync.WaitGroup
		const numGoroutines = 20
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.stop()
			}()
		}
		wg.Wait()

		select {
		case <-s.stopChan:
			// Expected: channel is closed
		default:
			t.Fatal("stopChan was not closed")
		}
	})
}
