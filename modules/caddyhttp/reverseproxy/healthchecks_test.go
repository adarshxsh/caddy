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

package reverseproxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestActiveHealthCheckConnectionReuseWithMaxSize(t *testing.T) {
	var connCount int32

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 10240))
	}))
	ts.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&connCount, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	h := &Handler{
		ctx:    caddyCtx,
		logger: zap.NewNop(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				URI:     "/health",
				MaxSize: 100,
			},
		},
		Transport: &http.Transport{},
	}

	err = h.HealthChecks.Active.Provision(caddyCtx, h)
	if err != nil {
		t.Fatalf("provisioning active health checks: %v", err)
	}

	upstream := &Upstream{
		Dial: u.Host,
		Host: new(Host),
	}

	dialInfo := DialInfo{
		Network: "tcp",
		Address: u.Host,
	}

	numRequests := 3
	for i := 0; i < numRequests; i++ {
		err := h.doActiveHealthCheck(dialInfo, u.Host, u.Host, upstream)
		if err != nil {
			t.Fatalf("health check %d failed: %v", i, err)
		}
	}

	if count := atomic.LoadInt32(&connCount); count != 1 {
		t.Errorf("expected 1 TCP connection created due to connection reuse, got %d for %d requests", count, numRequests)
	}
}
