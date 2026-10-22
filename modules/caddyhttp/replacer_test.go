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
	"strconv"
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

var sinkStr string
var sinkOk bool

func TestZeroAllocCookieHostPathLookups(t *testing.T) {
	// 1. Cookie Lookups
	t.Run("Cookies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Add("Cookie", "flavor=chocolate; size=large; user=\"john doe\"")
		req.Header.Add("Cookie", "session=abc123xyz")

		repl := caddy.NewReplacer()
		addHTTPVarsToReplacer(repl, req, nil)

		tests := []struct {
			name     string
			key      string
			expected string
			found    bool
		}{
			{"cookie flavor", "http.request.cookie.flavor", "chocolate", true},
			{"cookie Flavor case insensitive", "http.request.cookie.FLAVOR", "chocolate", true},
			{"cookie size", "http.request.cookie.size", "large", true},
			{"cookie quoted user", "http.request.cookie.user", "john doe", true},
			{"cookie second header line", "http.request.cookie.session", "abc123xyz", true},
			{"cookie nonexistent", "http.request.cookie.nonexistent", "", false},
		}

		for _, tc := range tests {
			val, ok := repl.GetString(tc.key)
			if ok != tc.found {
				t.Errorf("%s: expected found=%v, got %v", tc.name, tc.found, ok)
			}
			if val != tc.expected {
				t.Errorf("%s: expected value=%q, got %q", tc.name, tc.expected, val)
			}
		}

		// Allocation check for fastCookieLookup
		allocs := testing.AllocsPerRun(100, func() {
			sinkStr, sinkOk = fastCookieLookup(req, "session")
		})
		if allocs > 0 {
			t.Errorf("fastCookieLookup allocated %f objects, expected 0", allocs)
		}
	})

	// 2. Host Label Lookups
	t.Run("HostLabels", func(t *testing.T) {
		tests := []struct {
			host     string
			idx      int
			expected string
			found    bool
		}{
			{"sub.example.com:8080", 0, "com", true},
			{"sub.example.com:8080", 1, "example", true},
			{"sub.example.com:8080", 2, "sub", true},
			{"sub.example.com:8080", 3, "", true},
			{"sub.example.com", 0, "com", true},
			{"sub.example.com", 1, "example", true},
			{"sub.example.com", 2, "sub", true},
			{"localhost", 0, "localhost", true},
			{"localhost", 1, "", true},
			{"SUB.EXAMPLE.COM", 1, "example", true},
			{"[::1]:8080", 0, "::1", true},
			{"[::1]", 0, "[::1]", true},
			{"example.com", -1, "", false},
		}

		for _, tc := range tests {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tc.host
			repl := caddy.NewReplacer()
			addHTTPVarsToReplacer(repl, req, nil)

			key := "http.request.host.labels." + strconv.Itoa(tc.idx)
			if tc.idx < 0 {
				key = "http.request.host.labels.-1"
			}
			val, ok := repl.GetString(key)
			if ok != tc.found {
				t.Errorf("host=%q idx=%d: expected found=%v, got %v", tc.host, tc.idx, tc.found, ok)
			}
			if val != tc.expected {
				t.Errorf("host=%q idx=%d: expected value=%q, got %q", tc.host, tc.idx, tc.expected, val)
			}
		}

		// Allocation check for fastHostLabelLookup
		allocs := testing.AllocsPerRun(100, func() {
			sinkStr, sinkOk = fastHostLabelLookup("sub.example.com:8080", 1)
		})
		if allocs > 0 {
			t.Errorf("fastHostLabelLookup allocated %f objects, expected 0", allocs)
		}
	})

	// 3. URI Path & Original URI Path Lookups
	t.Run("URIPathParts", func(t *testing.T) {
		tests := []struct {
			path     string
			idx      int
			expected string
			found    bool
		}{
			{"/a/b/c", 0, "a", true},
			{"/a/b/c", 1, "b", true},
			{"/a/b/c", 2, "c", true},
			{"/a/b/c", 3, "", true},
			{"a/b/c", 0, "a", true},
			{"/a/b/", 2, "", true},
			{"/", 0, "", true},
			{"/", 1, "", true},
			{"", 0, "", true},
			{"/a//b", 1, "", true},
			{"/a//b", 2, "b", true},
		}

		for _, tc := range tests {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.Path = tc.path
			repl := caddy.NewReplacer()
			addHTTPVarsToReplacer(repl, req, nil)

			key := "http.request.uri.path." + strconv.Itoa(tc.idx)
			val, ok := repl.GetString(key)
			if ok != tc.found {
				t.Errorf("path=%q idx=%d: expected found=%v, got %v", tc.path, tc.idx, tc.found, ok)
			}
			if val != tc.expected {
				t.Errorf("path=%q idx=%d: expected value=%q, got %q", tc.path, tc.idx, tc.expected, val)
			}
		}

		// Test Original Request URI Path
		req := httptest.NewRequest(http.MethodGet, "/new/path", nil)
		origReq := httptest.NewRequest(http.MethodGet, "/orig/first/second", nil)
		ctx := context.WithValue(req.Context(), OriginalRequestCtxKey, *origReq)
		req = req.WithContext(ctx)

		repl := caddy.NewReplacer()
		addHTTPVarsToReplacer(repl, req, nil)

		val, ok := repl.GetString("http.request.orig_uri.path.0")
		if !ok || val != "orig" {
			t.Errorf("orig_uri.path.0: expected 'orig', got %q (ok=%v)", val, ok)
		}
		val, ok = repl.GetString("http.request.orig_uri.path.1")
		if !ok || val != "first" {
			t.Errorf("orig_uri.path.1: expected 'first', got %q (ok=%v)", val, ok)
		}

		// Allocation check for fastPathPartLookup
		allocs := testing.AllocsPerRun(100, func() {
			sinkStr, sinkOk = fastPathPartLookup("/a/b/c/d/e", 2)
		})
		if allocs > 0 {
			t.Errorf("fastPathPartLookup allocated %f objects, expected 0", allocs)
		}
	})
}

func BenchmarkReplacerZeroAllocLookups(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/123/profile", nil)
	req.Host = "api.v1.sub.example.com:8080"
	req.Header.Set("Cookie", "session_id=xyz123; theme=dark; lang=en-US")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.Run("Cookie", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = repl.GetString("http.request.cookie.theme")
		}
	})

	b.Run("HostLabel", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = repl.GetString("http.request.host.labels.2")
		}
	})

	b.Run("URIPath", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = repl.GetString("http.request.uri.path.2")
		}
	})

	b.Run("DirectCookieLookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = fastCookieLookup(req, "theme")
		}
	})

	b.Run("DirectHostLabelLookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = fastHostLabelLookup(req.Host, 2)
		}
	})

	b.Run("DirectPathPartLookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkStr, sinkOk = fastPathPartLookup(req.URL.Path, 2)
		}
	})
}
