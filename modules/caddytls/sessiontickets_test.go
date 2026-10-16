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

func TestSessionTicketServiceStopUninitialized(t *testing.T) {
	s := &SessionTicketService{}
	// stop() on uninitialized service where stopChan is nil should be a safe no-op
	s.stop()
	s.stop()
}

func TestSessionTicketServiceStopSequential(t *testing.T) {
	s := &SessionTicketService{
		stopChan: make(chan struct{}),
	}

	s.stop()

	select {
	case _, ok := <-s.stopChan:
		if ok {
			t.Errorf("expected stopChan to be closed")
		}
	default:
		t.Errorf("stopChan was not closed")
	}

	// Repeated calls to stop should be idempotent and not panic
	s.stop()
	s.stop()
}

func TestSessionTicketServiceStopConcurrent(t *testing.T) {
	s := &SessionTicketService{
		stopChan: make(chan struct{}),
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.stop()
		}()
	}

	wg.Wait()

	select {
	case _, ok := <-s.stopChan:
		if ok {
			t.Errorf("expected stopChan to be closed")
		}
	default:
		t.Errorf("stopChan was not closed")
	}
}
