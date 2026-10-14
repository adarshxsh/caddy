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

package caddyhttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(EarlyData{})
}

// EarlyData is a middleware handler that configures early data (0-RTT) policy for a route per RFC 8470.
type EarlyData struct {
	// Policy specifies the early data policy for this route.
	// Supported options are:
	// - "safe_only" (or "default"): Only safe HTTP methods (GET, HEAD, OPTIONS, TRACE) are allowed during 0-RTT early data.
	// - "allow": All HTTP methods are permitted during 0-RTT early data.
	// - "deny": All 0-RTT early data requests are rejected with 425 Too Early.
	Policy string `json:"policy,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (EarlyData) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.early_data",
		New: func() caddy.Module { return new(EarlyData) },
	}
}

// Provision sets up the EarlyData handler.
func (e *EarlyData) Provision(ctx caddy.Context) error {
	e.Policy = strings.ToLower(e.Policy)
	switch e.Policy {
	case "", "safe_only", "default", "allow", "deny", "reject", "permit":
		if e.Policy == "default" {
			e.Policy = "safe_only"
		} else if e.Policy == "permit" {
			e.Policy = "allow"
		} else if e.Policy == "reject" {
			e.Policy = "deny"
		}
	default:
		return fmt.Errorf("unrecognized early data policy '%s' (expected 'safe_only', 'allow', or 'deny')", e.Policy)
	}
	return nil
}

func (e EarlyData) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		switch e.Policy {
		case "deny":
			w.Header().Set("Too-Early", "1")
			w.WriteHeader(http.StatusTooEarly)
			return nil
		case "allow":
			return next.ServeHTTP(w, r)
		default: // "safe_only", "", etc.
			if !isSafeMethod(r.Method) {
				w.Header().Set("Too-Early", "1")
				w.WriteHeader(http.StatusTooEarly)
				return nil
			}
		}
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses Caddyfile syntax:
//
//	early_data [<policy>]
//
// Policy options: safe_only (default), allow, deny.
func (e *EarlyData) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() {
		e.Policy = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ MiddlewareHandler     = (*EarlyData)(nil)
	_ caddyfile.Unmarshaler = (*EarlyData)(nil)
	_ caddy.Provisioner     = (*EarlyData)(nil)
)
