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

func TestStandardSTEKProvider_Race(t *testing.T) {
	service := &caddytls.SessionTicketService{
		RotationInterval: caddy.Duration(10 * time.Millisecond),
		MaxKeys:          4,
	}

	provider := &standardSTEKProvider{}
	initKeys, err := provider.Initialize(service)
	if err != nil {
		t.Fatalf("failed to initialize provider: %v", err)
	}
	if len(initKeys) == 0 {
		t.Fatalf("expected non-empty initial keys")
	}

	doneChan := make(chan struct{})
	keysChan := provider.Next(doneChan)

	var wg sync.WaitGroup
	stopReader := make(chan struct{})

	// Readers accessing package level keys slice under RLock
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReader:
					return
				default:
					mutex.RLock()
					for _, k := range keys {
						_ = k[0]
					}
					mutex.RUnlock()
				}
			}
		}()
	}

	// Consumer reading updated keys from keysChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopReader:
				return
			case rotatedKeys, ok := <-keysChan:
				if !ok {
					return
				}
				for _, k := range rotatedKeys {
					_ = k[0]
				}
			}
		}
	}()

	// Allow rotation ticker to run several iterations
	time.Sleep(100 * time.Millisecond)

	close(doneChan)
	close(stopReader)
	wg.Wait()
}
