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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestSessionTicketRegistererInterface(t *testing.T) {
	// Verify compile-time interface implementation
	var _ caddy.SessionTicketRegisterer = (*SessionTicketService)(nil)
	var _ caddy.SessionTicketRegisterer = (*TLS)(nil)

	sts := &SessionTicketService{
		configs: make(map[*tls.Config]struct{}),
		mu:      new(sync.Mutex),
	}

	initialKeys := [][32]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	}
	sts.currentKeys = initialKeys

	tlsConf := new(tls.Config)

	// Test RegisterSessionTicket
	sts.RegisterSessionTicket(tlsConf)

	sts.mu.Lock()
	if _, ok := sts.configs[tlsConf]; !ok {
		t.Fatalf("expected tls.Config to be registered in SessionTicketService")
	}
	sts.mu.Unlock()

	// Test UnregisterSessionTicket
	sts.UnregisterSessionTicket(tlsConf)

	sts.mu.Lock()
	if _, ok := sts.configs[tlsConf]; ok {
		t.Fatalf("expected tls.Config to be unregistered from SessionTicketService")
	}
	sts.mu.Unlock()

	// Test TLS wrapper methods
	tlsApp := &TLS{SessionTickets: sts}
	tlsApp.RegisterSessionTicket(tlsConf)

	sts.mu.Lock()
	if _, ok := sts.configs[tlsConf]; !ok {
		t.Fatalf("expected tls.Config to be registered via TLS app")
	}
	sts.mu.Unlock()

	tlsApp.UnregisterSessionTicket(tlsConf)

	sts.mu.Lock()
	if _, ok := sts.configs[tlsConf]; ok {
		t.Fatalf("expected tls.Config to be unregistered via TLS app")
	}
	sts.mu.Unlock()
}

type mockSTEKProvider struct {
	keysChan chan [][32]byte
}

func (m *mockSTEKProvider) Initialize(config *SessionTicketService) ([][32]byte, error) {
	return [][32]byte{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}}, nil
}

func (m *mockSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	return m.keysChan
}

func TestSessionTicketStayUpdated(t *testing.T) {
	keysChan := make(chan [][32]byte)
	provider := &mockSTEKProvider{keysChan: keysChan}

	sts := &SessionTicketService{
		configs:   make(map[*tls.Config]struct{}),
		mu:        new(sync.Mutex),
		keySource: provider,
	}

	err := sts.start()
	if err != nil {
		t.Fatalf("unexpected error starting SessionTicketService: %v", err)
	}
	defer sts.stop()

	tlsConf := new(tls.Config)
	sts.RegisterSessionTicket(tlsConf)

	newKeys := [][32]byte{
		{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	}

	keysChan <- newKeys

	// Give time for stayUpdated goroutine to process key rotation
	time.Sleep(100 * time.Millisecond)

	sts.mu.Lock()
	if !reflect.DeepEqual(sts.currentKeys, newKeys) {
		t.Fatalf("expected currentKeys to be updated, got %#v, want %#v", sts.currentKeys, newKeys)
	}
	sts.mu.Unlock()
}
