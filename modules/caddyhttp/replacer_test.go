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
	"testing"
	"unsafe"

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

func TestHeaderAndQueryOptimization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?user=alice&token=xyz123&tags=a&tags=b", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("x-custom-lower", "custom-value")

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.Header().Add("X-Multi", "v1")
	rec.Header().Add("X-Multi", "v2")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, rec)

	// Query lookups
	val, ok := repl.GetString("http.request.uri.query.user")
	if !ok || val != "alice" {
		t.Errorf("expected user=alice, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.request.uri.query.token")
	if !ok || val != "xyz123" {
		t.Errorf("expected token=xyz123, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.request.uri.query.tags")
	if !ok || val != "a,b" {
		t.Errorf("expected tags=a,b, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.request.uri.query.missing")
	if !ok || val != "" {
		t.Errorf("expected missing query param to return empty string, got %q (ok=%t)", val, ok)
	}

	// Request header lookups (canonical direct map check)
	val, ok = repl.GetString("http.request.header.User-Agent")
	if !ok || val != "TestAgent/1.0" {
		t.Errorf("expected User-Agent=TestAgent/1.0, got %q (ok=%t)", val, ok)
	}
	// Request header lookup (non-canonical key lookup)
	val, ok = repl.GetString("http.request.header.user-agent")
	if !ok || val != "TestAgent/1.0" {
		t.Errorf("expected user-agent=TestAgent/1.0, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.request.header.X-Custom-Lower")
	if !ok || val != "custom-value" {
		t.Errorf("expected X-Custom-Lower=custom-value, got %q (ok=%t)", val, ok)
	}
	// Request header lookup (multi-value)
	val, ok = repl.GetString("http.request.header.Accept")
	if !ok || val != "text/html,application/json" {
		t.Errorf("expected Accept=text/html,application/json, got %q (ok=%t)", val, ok)
	}
	// Request header lookup (missing)
	val, ok = repl.GetString("http.request.header.X-Missing")
	if !ok || val != "" {
		t.Errorf("expected X-Missing to return empty string, got %q (ok=%t)", val, ok)
	}

	// Response header lookups
	val, ok = repl.GetString("http.response.header.Content-Type")
	if !ok || val != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.response.header.X-Multi")
	if !ok || val != "v1,v2" {
		t.Errorf("expected X-Multi=v1,v2, got %q (ok=%t)", val, ok)
	}
	val, ok = repl.GetString("http.response.header.X-Missing")
	if !ok || val != "" {
		t.Errorf("expected response X-Missing to return empty string, got %q (ok=%t)", val, ok)
	}
}

func BenchmarkSingleValueHeaderAndQueryLookups(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/test?user=alice&token=xyz123", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Set("Authorization", "Bearer my-secret-token")

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, rec)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.header.User-Agent")
		_, _ = repl.GetString("http.request.header.Authorization")
		_, _ = repl.GetString("http.request.uri.query.user")
		_, _ = repl.GetString("http.request.uri.query.token")
		_, _ = repl.GetString("http.response.header.Content-Type")
	}
}

func TestQueryCachingAndHeaderStringIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?user=alice&token=xyz123", nil)
	headerVal := "TestAgent/1.0"
	req.Header.Set("User-Agent", headerVal)

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	// 1. Verify single-value header lookup returns exact string reference (no strings.Join allocation)
	gotHeader, ok := repl.Get("http.request.header.User-Agent")
	if !ok {
		t.Fatalf("expected header lookup to succeed")
	}
	headerStr, isStr := gotHeader.(string)
	if !isStr {
		t.Fatalf("expected string result")
	}
	if unsafe.StringData(headerStr) != unsafe.StringData(req.Header["User-Agent"][0]) {
		t.Errorf("expected string pointer identity for single-value header lookup, but strings differed in memory location")
	}

	// 2. Verify query parameter is parsed at most once and cached
	val1, _ := repl.GetString("http.request.uri.query.user")
	if val1 != "alice" {
		t.Errorf("expected user=alice, got %q", val1)
	}

	// Mutate RawQuery to verify cached result is returned instead of re-parsing
	req.URL.RawQuery = "user=bob&token=modified"

	val2, _ := repl.GetString("http.request.uri.query.token")
	if val2 != "xyz123" {
		t.Errorf("expected cached token=xyz123 after RawQuery mutation, got %q", val2)
	}

	val3, _ := repl.GetString("http.request.uri.query.user")
	if val3 != "alice" {
		t.Errorf("expected cached user=alice, got %q", val3)
	}

	// 3. Verify single-value query parameter lookup returns exact string reference
	queryVal, ok := repl.Get("http.request.uri.query.token")
	if !ok {
		t.Fatalf("expected query lookup to succeed")
	}
	queryStr := queryVal.(string)
	if queryStr != "xyz123" {
		t.Errorf("expected queryStr=xyz123, got %q", queryStr)
	}
}
