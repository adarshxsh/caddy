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

var benchStringSink string

func TestZeroAllocHeaderAndQueryLookups(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/foo?a=val1&b=val2&multi=1&multi=2", nil)
	req.Header.Set("X-Single-Header", "single-val")
	req.Header.Set("x-uncanonical-header", "uncanonical-val")
	req.Header["X-Multi-Header"] = []string{"val1", "val2"}

	longKey := "X-Long-Header-Key-That-Exceeds-Sixty-Four-Bytes-Length-For-Stack-Buffer-Testing"
	req.Header.Set(longKey, "long-val")

	res := httptest.NewRecorder()
	res.Header().Set("X-Resp-Header", "resp-val")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, res)

	// Correctness assertions
	tests := []struct {
		key      string
		expected string
	}{
		{"http.request.header.X-Single-Header", "single-val"},
		{"http.request.header.x-single-header", "single-val"},
		{"http.request.header.x-uncanonical-header", "uncanonical-val"},
		{"http.request.header.X-Uncanonical-Header", "uncanonical-val"},
		{"http.request.header." + longKey, "long-val"},
		{"http.request.header.X-Missing-Header", ""},
		{"http.request.header.X-Multi-Header", "val1,val2"},
		{"http.response.header.X-Resp-Header", "resp-val"},
		{"http.response.header.x-resp-header", "resp-val"},
		{"http.response.header.X-Missing-Resp", ""},
		{"http.request.uri.query.a", "val1"},
		{"http.request.uri.query.b", "val2"},
		{"http.request.uri.query.missing", ""},
		{"http.request.uri.query.multi", "1,2"},
	}

	for _, tc := range tests {
		val, ok := repl.GetString(tc.key)
		if !ok {
			t.Errorf("expected key %q to be recognized", tc.key)
		}
		if val != tc.expected {
			t.Errorf("key %q: expected %q, got %q", tc.key, tc.expected, val)
		}
	}

	// Prime query cache
	_, _ = repl.GetString("http.request.uri.query.a")

	// Verify getHeader zero allocations
	allocs := testing.AllocsPerRun(100, func() {
		vals := getHeader(req.Header, "X-Single-Header")
		benchStringSink = vals[0]
	})
	if allocs > 0 {
		t.Errorf("expected 0 allocs for exact canonical getHeader, got %f", allocs)
	}

	allocs = testing.AllocsPerRun(100, func() {
		vals := getHeader(req.Header, "x-single-header")
		benchStringSink = vals[0]
	})
	if allocs > 0 {
		t.Errorf("expected 0 allocs for uncanonicalized getHeader, got %f", allocs)
	}

	allocs = testing.AllocsPerRun(100, func() {
		vals := getHeader(res.Header(), "X-Resp-Header")
		benchStringSink = vals[0]
	})
	if allocs > 0 {
		t.Errorf("expected 0 allocs for response getHeader, got %f", allocs)
	}

	// Verify cached query parameter lookup zero allocations
	allocs = testing.AllocsPerRun(100, func() {
		queryVals := req.Context().Value(parsedQueryCtxKey).(url.Values)
		vals := queryVals["b"]
		benchStringSink = joinValues(vals)
	})
	if allocs > 0 {
		t.Errorf("expected 0 allocs for cached query lookup, got %f", allocs)
	}
}

func BenchmarkHeaderLookup(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "Caddy/v2")
	req.Header.Set("x-custom-header", "custom-value")
	res := httptest.NewRecorder()
	res.Header().Set("Content-Type", "text/html")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, res)

	b.Run("ExactCanonical", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, _ := repl.GetString("http.request.header.User-Agent")
			benchStringSink = s
		}
	})

	b.Run("UncanonicalizedKey", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, _ := repl.GetString("http.request.header.user-agent")
			benchStringSink = s
		}
	})

	b.Run("ResponseHeader", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, _ := repl.GetString("http.response.header.Content-Type")
			benchStringSink = s
		}
	})
}

func BenchmarkQueryLookup(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar&baz=qux", nil)
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	// Warm up cache
	_, _ = repl.GetString("http.request.uri.query.foo")

	b.Run("CachedQueryLookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, _ := repl.GetString("http.request.uri.query.baz")
			benchStringSink = s
		}
	})
}
