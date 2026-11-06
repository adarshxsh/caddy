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

func TestSessionTicketService_StopIdempotent(t *testing.T) {
	t.Run("stop uninitialized service", func(t *testing.T) {
		service := &SessionTicketService{}
		// Should be a safe no-op on zero value / uninitialized struct
		service.stop()
		if service.stopChan != nil {
			t.Errorf("expected stopChan to be nil, got %v", service.stopChan)
		}
	})

	t.Run("stop single invocation", func(t *testing.T) {
		ch := make(chan struct{})
		service := &SessionTicketService{
			stopChan: ch,
		}

		service.stop()

		if service.stopChan != nil {
			t.Errorf("expected stopChan to be cleared to nil, got %v", service.stopChan)
		}

		select {
		case <-ch:
			// channel successfully closed
		default:
			t.Error("expected channel to be closed")
		}
	})

	t.Run("stop repeated sequential invocations", func(t *testing.T) {
		ch := make(chan struct{})
		service := &SessionTicketService{
			stopChan: ch,
		}

		// First call closes channel and clears reference
		service.stop()
		// Subsequent calls must be idempotent no-ops and not panic
		service.stop()
		service.stop()

		if service.stopChan != nil {
			t.Errorf("expected stopChan to be nil, got %v", service.stopChan)
		}
	})

	t.Run("stop concurrent invocations", func(t *testing.T) {
		ch := make(chan struct{})
		service := &SessionTicketService{
			stopChan: ch,
		}

		const numGoroutines = 20
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				service.stop()
			}()
		}

		wg.Wait()

		if service.stopChan != nil {
			t.Errorf("expected stopChan to be nil, got %v", service.stopChan)
		}

		select {
		case <-ch:
			// channel successfully closed
		default:
			t.Error("expected channel to be closed")
		}
	})
}
