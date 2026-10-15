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
	"net/textproto"
	"strings"
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

func TestCanonicalizeMIMEHeaderKeyInPlace(t *testing.T) {
	testKeys := []string{
		"user-agent",
		"content-type",
		"x-forwarded-for",
		"accept-encoding",
		"authorization",
		"sec-websocket-key",
		"strict-transport-security",
		"A-B-C-D-E-F",
		"x-custom_header-test",
		"Host",
		"cookie",
	}

	for _, rawKey := range testKeys {
		expected := textproto.CanonicalMIMEHeaderKey(rawKey)
		buf := make([]byte, len(rawKey))
		canonicalizeMIMEHeaderKeyInPlace(buf, rawKey)
		got := string(buf)
		if got != expected {
			t.Errorf("canonicalizeMIMEHeaderKeyInPlace(%q): got %q, expected %q", rawKey, got, expected)
		}
	}
}

func TestQueryParamParsing(t *testing.T) {
	for i, tc := range []struct {
		rawQuery string
		paramKey string
		expect   string
	}{
		{rawQuery: "a=1&b=2", paramKey: "a", expect: "1"},
		{rawQuery: "a=1&b=2", paramKey: "b", expect: "2"},
		{rawQuery: "a=1&b=2", paramKey: "c", expect: ""},
		{rawQuery: "a=1&a=2&a=3", paramKey: "a", expect: "1,2,3"},
		{rawQuery: "a=hello%20world&b=foo+bar", paramKey: "a", expect: "hello world"},
		{rawQuery: "a=hello%20world&b=foo+bar", paramKey: "b", expect: "foo bar"},
		{rawQuery: "foo%20bar=baz", paramKey: "foo bar", expect: "baz"},
		{rawQuery: "a=1;b=2", paramKey: "a", expect: "1"},
		{rawQuery: "a=1;b=2", paramKey: "b", expect: "2"},
		{rawQuery: "a=&b=2", paramKey: "a", expect: ""},
		{rawQuery: "a&b=2", paramKey: "a", expect: ""},
		{rawQuery: "", paramKey: "a", expect: ""},
	} {
		req, _ := http.NewRequest(http.MethodGet, "/test?"+tc.rawQuery, nil)
		repl := caddy.NewReplacer()
		addHTTPVarsToReplacer(repl, req, nil)

		val, ok := repl.GetString("http.request.uri.query." + tc.paramKey)
		if !ok {
			t.Errorf("Test %d: expected to recognize placeholder http.request.uri.query.%s", i, tc.paramKey)
		}
		if val != tc.expect {
			t.Errorf("Test %d: expected query param %q to be %q, got %q", i, tc.paramKey, tc.expect, val)
		}
	}
}

func TestHeaderReplacer(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "Caddy/v2")
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Accept", "application/json")

	longHeaderName := "X-Very-Long-Header-Name-That-Exceeds-The-64-Byte-Stack-Buffer-Capacity-Limit-For-Testing"
	req.Header.Set(longHeaderName, "long-value")

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, rec)

	// Canonical case request header
	if val, ok := repl.GetString("http.request.header.User-Agent"); !ok || val != "Caddy/v2" {
		t.Errorf("expected User-Agent to be 'Caddy/v2', got %q (ok=%t)", val, ok)
	}

	// Lowercase request header
	if val, ok := repl.GetString("http.request.header.user-agent"); !ok || val != "Caddy/v2" {
		t.Errorf("expected user-agent to be 'Caddy/v2', got %q (ok=%t)", val, ok)
	}

	// Multi-value request header
	if val, ok := repl.GetString("http.request.header.Accept"); !ok || val != "text/html,application/json" {
		t.Errorf("expected Accept to be 'text/html,application/json', got %q (ok=%t)", val, ok)
	}

	// Long header exceeding stack buffer
	if val, ok := repl.GetString("http.request.header." + longHeaderName); !ok || val != "long-value" {
		t.Errorf("expected long header to be 'long-value', got %q (ok=%t)", val, ok)
	}

	// Lowercase long header
	if val, ok := repl.GetString("http.request.header." + strings.ToLower(longHeaderName)); !ok || val != "long-value" {
		t.Errorf("expected lowercase long header to be 'long-value', got %q (ok=%t)", val, ok)
	}

	// Response header
	if val, ok := repl.GetString("http.response.header.Content-Type"); !ok || val != "application/json" {
		t.Errorf("expected response Content-Type to be 'application/json', got %q (ok=%t)", val, ok)
	}

	// Missing header
	if val, ok := repl.GetString("http.request.header.X-Non-Existent"); !ok || val != "" {
		t.Errorf("expected missing header to be '', got %q (ok=%t)", val, ok)
	}
}

func BenchmarkQueryParamReplacerSingleValue(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "/test?api_key=12345&user=john", nil)
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.uri.query.api_key")
	}
}

func BenchmarkParseURLQueryParamDirect(b *testing.B) {
	rawQuery := "api_key=12345&user=john"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseURLQueryParam(rawQuery, "api_key")
	}
}

func BenchmarkGetMIMEHeaderValueCanonicalDirect(b *testing.B) {
	h := make(http.Header)
	h.Set("User-Agent", "Mozilla/5.0")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getMIMEHeaderValue(h, "User-Agent")
	}
}

func BenchmarkGetMIMEHeaderValueNonCanonicalDirect(b *testing.B) {
	h := make(http.Header)
	h.Set("User-Agent", "Mozilla/5.0")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getMIMEHeaderValue(h, "user-agent")
	}
}

func BenchmarkQueryParamReplacerMultiValue(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "/test?tag=go&tag=caddy&tag=http", nil)
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.uri.query.tag")
	}
}

func BenchmarkHeaderReplacerCanonical(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.header.User-Agent")
	}
}

func BenchmarkHeaderReplacerNonCanonicalStack(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.header.user-agent")
	}
}

func BenchmarkHeaderReplacerFallbackLong(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	longHeaderName := "X-Very-Long-Header-Name-That-Exceeds-The-64-Byte-Stack-Buffer-Capacity-Limit-For-Testing"
	req.Header.Set(longHeaderName, "value")
	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = repl.GetString("http.request.header." + strings.ToLower(longHeaderName))
	}
}
