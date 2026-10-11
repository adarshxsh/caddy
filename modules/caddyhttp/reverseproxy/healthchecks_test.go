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
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func TestActiveHealthCheckBodyDrainingConnectionReuse(t *testing.T) {
	var connCount int32

	// Create test server returning a body much larger than MaxSize
	largeResponseBody := bytes.Repeat([]byte("X"), 10000)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(largeResponseBody)
	}))
	ts.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&connCount, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	hostAddr := u.Host

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	eventsApp := &caddyevents.App{}
	if err := eventsApp.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision events app: %v", err)
	}

	h := &Handler{
		ctx:       caddyCtx,
		logger:    zap.NewNop(),
		events:    eventsApp,
		Transport: &http.Transport{},
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				URI:     "/health",
				MaxSize: 100, // MaxSize is 100 bytes, response is 10,000 bytes
			},
		},
	}

	if err := h.HealthChecks.Active.Provision(caddyCtx, h); err != nil {
		t.Fatalf("failed to provision active health checks: %v", err)
	}

	upstreamHost := &Host{}
	upstream := &Upstream{
		Dial: hostAddr,
		Host: upstreamHost,
	}
	dialInfo := DialInfo{
		Upstream: upstream,
	}

	// Perform 1st health check
	err = h.doActiveHealthCheck(dialInfo, hostAddr, hostAddr, upstream)
	if err != nil {
		t.Fatalf("1st health check failed unexpectedly: %v", err)
	}
	if !upstream.Healthy() {
		t.Fatalf("upstream should be healthy after 1st health check")
	}

	// Perform 2nd health check
	err = h.doActiveHealthCheck(dialInfo, hostAddr, hostAddr, upstream)
	if err != nil {
		t.Fatalf("2nd health check failed unexpectedly: %v", err)
	}
	if !upstream.Healthy() {
		t.Fatalf("upstream should be healthy after 2nd health check")
	}

	// Because resp.Body is fully drained to EOF in defer, the underlying TCP connection
	// must be reused for the 2nd health check, resulting in only 1 new connection.
	if count := atomic.LoadInt32(&connCount); count != 1 {
		t.Errorf("expected 1 TCP connection created across 2 health checks, got %d", count)
	}
}

func TestActiveHealthCheckExpectBodyWithMaxSize(t *testing.T) {
	var connCount int32

	// Response body starts with "HEALTHY_OK" then padded with 5,000 extra bytes
	responseBody := append([]byte("HEALTHY_OK"), bytes.Repeat([]byte("-"), 5000)...)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}))
	ts.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&connCount, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	hostAddr := u.Host

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	eventsApp := &caddyevents.App{}
	if err := eventsApp.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision events app: %v", err)
	}

	h := &Handler{
		ctx:       caddyCtx,
		logger:    zap.NewNop(),
		events:    eventsApp,
		Transport: &http.Transport{},
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				URI:        "/health",
				MaxSize:    50, // Limit body reading for expect_body regex to 50 bytes
				ExpectBody: "HEALTHY_OK",
			},
		},
	}

	if err := h.HealthChecks.Active.Provision(caddyCtx, h); err != nil {
		t.Fatalf("failed to provision active health checks: %v", err)
	}

	upstream := &Upstream{
		Dial: hostAddr,
		Host: &Host{},
	}
	dialInfo := DialInfo{
		Upstream: upstream,
	}

	// Perform 1st health check
	if err := h.doActiveHealthCheck(dialInfo, hostAddr, hostAddr, upstream); err != nil {
		t.Fatalf("1st health check failed: %v", err)
	}

	// Perform 2nd health check
	if err := h.doActiveHealthCheck(dialInfo, hostAddr, hostAddr, upstream); err != nil {
		t.Fatalf("2nd health check failed: %v", err)
	}

	// Verify connection reuse
	if count := atomic.LoadInt32(&connCount); count != 1 {
		t.Errorf("expected 1 TCP connection, got %d", count)
	}
}
