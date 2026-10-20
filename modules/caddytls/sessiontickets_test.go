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
	done chan struct{}
}

func (d *dummySTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 2, 3}}, nil
}

func (d *dummySTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	ch := make(chan [][32]byte)
	go func() {
		<-doneChan
		if d.done != nil {
			close(d.done)
		}
	}()
	return ch
}

func TestSessionTicketServiceStop(t *testing.T) {
	t.Run("nil receiver or nil stopChan", func(t *testing.T) {
		var s *SessionTicketService
		// Calling stop on nil receiver should not panic
		s.stop()

		s2 := &SessionTicketService{}
		// Calling stop on uninitialized service should not panic
		s2.stop()
	})

	t.Run("sequential stop calls", func(t *testing.T) {
		stek := &dummySTEKProvider{done: make(chan struct{})}
		s := &SessionTicketService{
			keySource: stek,
			mu:        new(sync.Mutex),
		}

		if err := s.start(); err != nil {
			t.Fatalf("start failed: %v", err)
		}

		// First stop
		s.stop()
		<-stek.done

		// Subsequent stop calls should not panic
		s.stop()
		s.stop()
	})

	t.Run("concurrent stop calls", func(t *testing.T) {
		stek := &dummySTEKProvider{done: make(chan struct{})}
		s := &SessionTicketService{
			keySource: stek,
			mu:        new(sync.Mutex),
		}

		if err := s.start(); err != nil {
			t.Fatalf("start failed: %v", err)
		}

		const goroutines = 50
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				s.stop()
			}()
		}

		wg.Wait()
		<-stek.done
	})
}
