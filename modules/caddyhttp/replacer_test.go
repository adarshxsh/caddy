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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestHTTPVarReplacement(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/foo/bar.tar.gz?a=1&b=2", nil)
	repl := caddy.NewReplacer()
	localAddr, _ := net.ResolveTCPAddr("tcp", "192.168.159.1:80")
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, localAddr)
	req = req.WithContext(ctx)
	req.Host = "example.com:80"
	req.RemoteAddr = "192.168.159.32:1234"

	clientCert := []byte(`-----BEGIN CERTIFICATE-----
MIIB9jCCAV+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1DYWRk
eSBUZXN0IENBMB4XDTE4MDcyNDIxMzUwNVoXDTI4MDcyMTIxMzUwNVowHTEbMBkG
A1UEAwwSY2xpZW50LmxvY2FsZG9tYWluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDFDEpzF0ew68teT3xDzcUxVFaTII+jXH1ftHXxxP4BEYBU4q90qzeKFneF
z83I0nC0WAQ45ZwHfhLMYHFzHPdxr6+jkvKPASf0J2v2HDJuTM1bHBbik5Ls5eq+
fVZDP8o/VHKSBKxNs8Goc2NTsr5b07QTIpkRStQK+RJALk4x9QIDAQABo0swSTAJ
BgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8A
AAEwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADgYEANSjz2Sk+
eqp31wM9il1n+guTNyxJd+FzVAH+hCZE5K+tCgVDdVFUlDEHHbS/wqb2PSIoouLV
3Q9fgDkiUod+uIK0IynzIKvw+Cjg+3nx6NQ0IM0zo8c7v398RzB4apbXKZyeeqUH
9fNwfEi+OoXR6s+upSKobCmLGLGi9Na5s5g=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(clientCert)
	if block == nil {
		t.Fatalf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to decode PEM certificate: %v", err)
	}

	req.TLS = &tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		ServerName:                 "example.com",
		CipherSuite:                tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates:           []*x509.Certificate{cert},
		NegotiatedProtocol:         "h2",
		NegotiatedProtocolIsMutual: true,
	}

	res := httptest.NewRecorder()
	addHTTPVarsToReplacer(repl, req, res)

	for i, tc := range []struct {
		get    string
		expect string
	}{
		{
			get:    "http.request.scheme",
			expect: "https",
		},
		{
			get:    "http.request.method",
			expect: http.MethodGet,
		},
		{
			get:    "http.request.host",
			expect: "example.com",
		},
		{
			get:    "http.request.port",
			expect: "80",
		},
		{
			get:    "http.request.hostport",
			expect: "example.com:80",
		},
		{
			get:    "http.request.local.host",
			expect: "192.168.159.1",
		},
		{
			get:    "http.request.local.port",
			expect: "80",
		},
		{
			get:    "http.request.local",
			expect: "192.168.159.1:80",
		},
		{
			get:    "http.request.remote.host",
			expect: "192.168.159.32",
		},
		{
			get:    "http.request.remote.host/24",
			expect: "192.168.159.0/24",
		},
		{
			get:    "http.request.remote.host/24,32",
			expect: "192.168.159.0/24",
		},
		{
			get:    "http.request.remote.host/999",
			expect: "",
		},
		{
			get:    "http.request.remote.port",
			expect: "1234",
		},
		{
			get:    "http.request.host.labels.0",
			expect: "com",
		},
		{
			get:    "http.request.host.labels.1",
			expect: "example",
		},
		{
			get:    "http.request.host.labels.2",
			expect: "",
		},
		{
			get:    "http.request.uri",
			expect: "/foo/bar.tar.gz?a=1&b=2",
		},
		{
			get:    "http.request.uri_escaped",
			expect: "%2Ffoo%2Fbar.tar.gz%3Fa%3D1%26b%3D2",
		},
		{
			get:    "http.request.uri.path",
			expect: "/foo/bar.tar.gz",
		},
		{
			get:    "http.request.uri.path_escaped",
			expect: "%2Ffoo%2Fbar.tar.gz",
		},
		{
			get:    "http.request.uri.path.file",
			expect: "bar.tar.gz",
		},
		{
			get:    "http.request.uri.path.file.base",
			expect: "bar.tar",
		},
		{
			// not ideal, but also most correct, given that files can have dots (example: index.<SHA>.html) TODO: maybe this isn't right..
			get:    "http.request.uri.path.file.ext",
			expect: ".gz",
		},
		{
			get:    "http.request.uri.query",
			expect: "a=1&b=2",
		},
		{
			get:    "http.request.uri.query_escaped",
			expect: "a%3D1%26b%3D2",
		},
		{
			get:    "http.request.uri.query.a",
			expect: "1",
		},
		{
			get:    "http.request.uri.query.b",
			expect: "2",
		},
		{
			get:    "http.request.uri.prefixed_query",
			expect: "?a=1&b=2",
		},
		{
			get:    "http.request.tls.cipher_suite",
			expect: "TLS_AES_256_GCM_SHA384",
		},
		{
			get:    "http.request.tls.proto",
			expect: "h2",
		},
		{
			get:    "http.request.tls.proto_mutual",
			expect: "true",
		},
		{
			get:    "http.request.tls.resumed",
			expect: "false",
		},
		{
			get:    "http.request.tls.server_name",
			expect: "example.com",
		},
		{
			get:    "http.request.tls.version",
			expect: "tls1.3",
		},
		{
			get:    "http.request.tls.client.fingerprint",
			expect: "9f57b7b497cceacc5459b76ac1c3afedbc12b300e728071f55f84168ff0f7702",
		},
		{
			get:    "http.request.tls.client.issuer",
			expect: "CN=Caddy Test CA",
		},
		{
			get:    "http.request.tls.client.serial",
			expect: "2",
		},
		{
			get:    "http.request.tls.client.subject",
			expect: "CN=client.localdomain",
		},
		{
			get:    "http.request.tls.client.san.dns_names",
			expect: "[localhost]",
		},
		{
			get:    "http.request.tls.client.san.dns_names.0",
			expect: "localhost",
		},
		{
			get:    "http.request.tls.client.san.dns_names.1",
			expect: "",
		},
		{
			get:    "http.request.tls.client.san.ips",
			expect: "[127.0.0.1]",
		},
		{
			get:    "http.request.tls.client.san.ips.0",
			expect: "127.0.0.1",
		},
		{
			get:    "http.request.tls.client.certificate_pem",
			expect: string(clientCert) + "\n", // returned value comes with a newline appended to it
		},
	} {
		actual, got := repl.GetString(tc.get)
		if !got {
			t.Errorf("Test %d: Expected to recognize the placeholder name, but didn't", i)
		}
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %s to be '%s' but got '%s'",
				i, tc.get, tc.expect, actual)
		}
	}
}

func TestHTTPProtoNameNormalization(t *testing.T) {
	for _, tc := range []struct {
		proto      string
		major      int
		expectRaw  string
		expectName string
	}{
		{proto: "HTTP/1.0", major: 1, expectRaw: "HTTP/1.0", expectName: "HTTP/1.0"},
		{proto: "HTTP/1.1", major: 1, expectRaw: "HTTP/1.1", expectName: "HTTP/1.1"},
		{proto: "HTTP/2.0", major: 2, expectRaw: "HTTP/2.0", expectName: "HTTP/2"},
		{proto: "HTTP/3.0", major: 3, expectRaw: "HTTP/3.0", expectName: "HTTP/3"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Proto = tc.proto
		req.ProtoMajor = tc.major
		repl := caddy.NewReplacer()
		addHTTPVarsToReplacer(repl, req, nil)

		gotRaw, okRaw := repl.GetString("http.request.proto")
		if !okRaw || gotRaw != tc.expectRaw {
			t.Errorf("proto=%s: expected http.request.proto to be %q, got %q (ok=%t)", tc.proto, tc.expectRaw, gotRaw, okRaw)
		}

		gotName, okName := repl.GetString("http.request.proto_name")
		if !okName || gotName != tc.expectName {
			t.Errorf("proto=%s: expected http.request.proto_name to be %q, got %q (ok=%t)", tc.proto, tc.expectName, gotName, okName)
		}
	}
}

func TestReplacerMemoizationCache(t *testing.T) {
	t.Run("IPv4 and standard TCP", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/path?a=1&b=2", nil)
		repl := caddy.NewReplacer()
		localAddr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:8080")
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, http.LocalAddrContextKey, localAddr)
		req = req.WithContext(ctx)
		req.Host = "sub.example.com:80"
		req.RemoteAddr = "10.0.0.1:12345"

		var url2 url.URL
		ctx = context.WithValue(req.Context(), OriginalRequestCtxKey, originalRequest(req, &url2))
		req = req.WithContext(ctx)

		addHTTPVarsToReplacer(repl, req, nil)

		keys := []string{
			"http.request.host",
			"http.request.port",
			"http.request.host.labels.0",
			"http.request.host.labels.1",
			"http.request.local.host",
			"http.request.local.port",
			"http.request.remote.host",
			"http.request.remote.port",
			"http.request.remote.host/24",
			"http.request.remote.host/16",
			"http.request.uri.prefixed_query",
			"http.request.orig_uri.prefixed_query",
		}

		// First pass
		firstPass := make(map[string]string)
		for _, key := range keys {
			val, ok := repl.GetString(key)
			if !ok {
				t.Fatalf("key %s not found on first access", key)
			}
			firstPass[key] = val
		}

		// Second pass (cached)
		for _, key := range keys {
			val, ok := repl.GetString(key)
			if !ok {
				t.Fatalf("key %s not found on second access", key)
			}
			if val != firstPass[key] {
				t.Fatalf("key %s mismatch on second access: got %q, expected %q", key, val, firstPass[key])
			}
		}

		// Verify 0 allocations on subsequent accesses
		allocs := testing.AllocsPerRun(10, func() {
			for _, key := range keys {
				repl.Get(key)
			}
		})
		if allocs > 0 {
			t.Errorf("Expected 0 allocations on cached replacer lookups, got %f", allocs)
		}
	})

	t.Run("IPv6 and empty query string", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/path", nil)
		repl := caddy.NewReplacer()
		localAddr, _ := net.ResolveTCPAddr("tcp", "[2001:db8::1]:8080")
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, http.LocalAddrContextKey, localAddr)
		req = req.WithContext(ctx)
		req.Host = "[2001:db8::2]:443"
		req.RemoteAddr = "[2001:db8::3]:54321"

		var url2 url.URL
		ctx = context.WithValue(req.Context(), OriginalRequestCtxKey, originalRequest(req, &url2))
		req = req.WithContext(ctx)

		addHTTPVarsToReplacer(repl, req, nil)

		keys := []string{
			"http.request.host",
			"http.request.port",
			"http.request.local.host",
			"http.request.local.port",
			"http.request.remote.host",
			"http.request.remote.port",
			"http.request.remote.host/32,64",
			"http.request.uri.prefixed_query",
			"http.request.orig_uri.prefixed_query",
		}

		firstPass := make(map[string]string)
		for _, key := range keys {
			val, ok := repl.GetString(key)
			if !ok {
				t.Fatalf("key %s not found on first access", key)
			}
			firstPass[key] = val
		}

		if got := firstPass["http.request.remote.host/32,64"]; got != "2001:db8::/64" {
			t.Errorf("Expected IPv6 prefix 2001:db8::/64, got %q", got)
		}
		if got := firstPass["http.request.uri.prefixed_query"]; got != "" {
			t.Errorf("Expected empty prefixed query, got %q", got)
		}

		// Second pass (cached)
		for _, key := range keys {
			val, ok := repl.GetString(key)
			if !ok {
				t.Fatalf("key %s not found on second access", key)
			}
			if val != firstPass[key] {
				t.Fatalf("key %s mismatch on second access: got %q, expected %q", key, val, firstPass[key])
			}
		}

		allocs := testing.AllocsPerRun(10, func() {
			for _, key := range keys {
				repl.Get(key)
			}
		})
		if allocs > 0 {
			t.Errorf("Expected 0 allocations on cached IPv6 replacer lookups, got %f", allocs)
		}
	})

	t.Run("Unix socket fallback", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/path", nil)
		repl := caddy.NewReplacer()
		unixAddr := &net.UnixAddr{Name: "/var/run/caddy.sock", Net: "unix"}
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, http.LocalAddrContextKey, unixAddr)
		req = req.WithContext(ctx)
		req.Host = "unix-host"
		req.RemoteAddr = "/var/run/client.sock"

		addHTTPVarsToReplacer(repl, req, nil)

		host, ok := repl.GetString("http.request.remote.host")
		if !ok || host != "/var/run/client.sock" {
			t.Errorf("Expected remote.host unix socket '/var/run/client.sock', got %q (ok=%t)", host, ok)
		}

		port, ok := repl.GetString("http.request.remote.port")
		if !ok || port != "" {
			t.Errorf("Expected empty remote.port for unix socket, got %q (ok=%t)", port, ok)
		}

		// Second access cached
		hostCached, _ := repl.GetString("http.request.remote.host")
		if hostCached != host {
			t.Errorf("Mismatch cached unix socket host: got %q, expected %q", hostCached, host)
		}
	})

	t.Run("PrepareRequest cache re-initialization", func(t *testing.T) {
		repl1 := caddy.NewReplacer()
		req1, _ := http.NewRequest(http.MethodGet, "/?q=1", nil)
		req1.Host = "first.com:80"
		req1.RemoteAddr = "1.1.1.1:1111"
		req1 = PrepareRequest(req1, repl1, nil, nil)

		host1, _ := repl1.GetString("http.request.host")
		prefix1, _ := repl1.GetString("http.request.remote.host/24")
		query1, _ := repl1.GetString("http.request.uri.prefixed_query")

		if host1 != "first.com" || prefix1 != "1.1.1.0/24" || query1 != "?q=1" {
			t.Fatalf("Unexpected req1 values: host=%s prefix=%s query=%s", host1, prefix1, query1)
		}

		repl2 := caddy.NewReplacer()
		req2, _ := http.NewRequest(http.MethodGet, "/?q=2", nil)
		req2.Host = "second.com:80"
		req2.RemoteAddr = "2.2.2.2:2222"
		req2 = PrepareRequest(req2, repl2, nil, nil)

		host2, _ := repl2.GetString("http.request.host")
		prefix2, _ := repl2.GetString("http.request.remote.host/24")
		query2, _ := repl2.GetString("http.request.uri.prefixed_query")

		if host2 != "second.com" || prefix2 != "2.2.2.0/24" || query2 != "?q=2" {
			t.Fatalf("Unexpected req2 values: host=%s prefix=%s query=%s", host2, prefix2, query2)
		}
	})
}

