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
	"testing"
	"time"
)

func TestTLSStop(t *testing.T) {
	tlsApp := &TLS{
		storageCleanTicker: time.NewTicker(time.Hour),
		storageCleanStop:   make(chan struct{}),
	}

	// First Stop call should close the channel and stop the ticker
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("first Stop() failed: %v", err)
	}

	if tlsApp.storageCleanStop != nil {
		t.Errorf("expected storageCleanStop to be nil after Stop()")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Errorf("expected storageCleanTicker to be nil after Stop()")
	}

	// Calling Stop again should not panic
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("second Stop() failed: %v", err)
	}

	// Calling Stop on a zero TLS struct should also work without panic
	zeroTLS := &TLS{}
	if err := zeroTLS.Stop(); err != nil {
		t.Fatalf("Stop() on zero TLS struct failed: %v", err)
	}
}
