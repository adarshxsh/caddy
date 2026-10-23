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

func TestSessionTicketService_Stop(t *testing.T) {
	t.Run("nil stopChan", func(t *testing.T) {
		s := &SessionTicketService{}
		// Calling stop when stopChan is nil should not panic
		s.stop()
	})

	t.Run("sequential stop calls", func(t *testing.T) {
		s := &SessionTicketService{
			stopChan: make(chan struct{}),
		}

		s.stop()

		// Verify channel is closed
		select {
		case _, ok := <-s.stopChan:
			if ok {
				t.Errorf("expected stopChan to be closed, but received a value")
			}
		default:
			t.Errorf("expected stopChan to be closed, but read would block")
		}

		// Subsequent calls must be safe and idempotent (no panic)
		s.stop()
		s.stop()
	})

	t.Run("concurrent stop calls", func(t *testing.T) {
		s := &SessionTicketService{
			stopChan: make(chan struct{}),
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

		// Verify channel is closed
		select {
		case _, ok := <-s.stopChan:
			if ok {
				t.Errorf("expected stopChan to be closed, but received a value")
			}
		default:
			t.Errorf("expected stopChan to be closed, but read would block")
		}
	})
}
