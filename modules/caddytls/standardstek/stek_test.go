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

package standardstek

import (
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestSTEKRotation_Race(t *testing.T) {
	s := new(standardSTEKProvider)
	stekConfig := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(5 * time.Millisecond),
		MaxKeys:          4,
	}

	initKeys, err := s.Initialize(stekConfig)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatal("expected non-empty initial keys")
	}

	doneChan := make(chan struct{})
	keysChan := s.Next(doneChan)

	var wg sync.WaitGroup

	// Goroutine reading from keysChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-keysChan:
			case <-doneChan:
				return
			}
		}
	}()

	// Goroutines performing concurrent reads on global keys under RLock
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-doneChan:
					return
				default:
					mutex.RLock()
					for _, k := range keys {
						_ = k[0]
					}
					mutex.RUnlock()
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Allow several rotations to occur while concurrent reads happen
	time.Sleep(100 * time.Millisecond)

	close(doneChan)
	wg.Wait()
}
