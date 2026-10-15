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

func TestSessionTicketServiceRegisterUnregister(t *testing.T) {
	sts := &SessionTicketService{
		configs:     make(map[*tls.Config]struct{}),
		mu:          new(sync.Mutex),
		currentKeys: [][32]byte{{1, 2, 3}},
	}

	cfg1 := &tls.Config{}
	cfg2 := &tls.Config{}

	sts.Register(cfg1)
	if len(sts.configs) != 1 {
		t.Fatalf("expected 1 config registered, got %d", len(sts.configs))
	}

	sts.Register(cfg2)
	if len(sts.configs) != 2 {
		t.Fatalf("expected 2 configs registered, got %d", len(sts.configs))
	}

	sts.Unregister(cfg1)
	if len(sts.configs) != 1 {
		t.Fatalf("expected 1 config remaining after unregistering cfg1, got %d", len(sts.configs))
	}

	if _, ok := sts.configs[cfg2]; !ok {
		t.Fatalf("expected cfg2 to still be registered")
	}

	sts.Unregister(cfg2)
	if len(sts.configs) != 0 {
		t.Fatalf("expected 0 configs remaining, got %d", len(sts.configs))
	}
}

func TestTLSRegisterUnregister(t *testing.T) {
	sts := &SessionTicketService{
		configs:     make(map[*tls.Config]struct{}),
		mu:          new(sync.Mutex),
		currentKeys: [][32]byte{{4, 5, 6}},
	}
	tlsApp := &TLS{
		SessionTickets: sts,
	}

	cfg := &tls.Config{}
	tlsApp.Register(cfg)
	if len(sts.configs) != 1 {
		t.Fatalf("expected 1 config registered via TLS app, got %d", len(sts.configs))
	}

	tlsApp.Unregister(cfg)
	if len(sts.configs) != 0 {
		t.Fatalf("expected 0 configs remaining after unregister via TLS app, got %d", len(sts.configs))
	}
}
