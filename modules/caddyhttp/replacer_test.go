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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestMissingCookiePlaceholder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), VarsCtxKey, map[string]any{}))
	repl := NewTestReplacer(req)
	const input = "before-{http.request.cookie.session}-after"
	if got := repl.ReplaceKnown(input, ""); got != "before--after" {
		t.Fatalf("missing cookie = %q, want %q", got, "before--after")
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "present"})
	if got := repl.ReplaceKnown(input, ""); got != "before-present-after" {
		t.Fatalf("present cookie = %q, want %q", got, "before-present-after")
	}
}

func TestTLSPlaceholdersWithoutTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), VarsCtxKey, map[string]any{}))
	repl := NewTestReplacer(req)
	for _, field := range []string{
		"version", "cipher_suite", "resumed", "proto", "proto_mutual", "server_name", "ech",
		"client.fingerprint", "client.public_key", "client.public_key_sha256",
		"client.issuer", "client.serial", "client.subject", "client.certificate_pem", "client.certificate_der_base64",
		"client.san.dns_names", "client.san.emails", "client.san.ips", "client.san.uris",
		"client.san.dns_names.0", "client.san.emails.0", "client.san.ips.0", "client.san.uris.0",
	} {
		t.Run(field, func(t *testing.T) {
			key := "http.request.tls." + field
			value, known := repl.Get(key)
			if !known || caddy.ToString(value) != "" {
				t.Fatalf("Get(%q) = %v, %v; want empty, known", key, value, known)
			}
			if got := repl.ReplaceKnown("before-{"+key+"}-after", ""); got != "before--after" {
				t.Fatalf("replacement = %q, want %q", got, "before--after")
			}
		})
	}
}

func TestUnknownTLSPlaceholdersRemainLiteral(t *testing.T) {
	for _, state := range []*tls.ConnectionState{nil, {ServerName: "example.com"}} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.TLS = state
		req = req.WithContext(context.WithValue(req.Context(), VarsCtxKey, map[string]any{}))
		repl := NewTestReplacer(req)
		for _, field := range []string{
			"unknown", "client.unknown", "client.san.unknown",
			"client.san.dns_names_extra", "client.san.dns_names.-1", "client.san.dns_names.nope",
		} {
			input := "{http.request.tls." + field + "}"
			if got := repl.ReplaceKnown(input, ""); got != input {
				t.Errorf("replacement = %q, want literal %q", got, input)
			}
		}
	}
}

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

func TestHTTPVarsMemoization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?foo=bar", nil)
	localAddr, _ := net.ResolveTCPAddr("tcp", "10.0.0.1:8080")
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey, localAddr)

	origReq := *httptest.NewRequest(http.MethodGet, "/orig?baz=qux", nil)
	ctx = context.WithValue(ctx, OriginalRequestCtxKey, origReq)

	req = req.WithContext(ctx)
	req.RemoteAddr = "192.168.1.100:54321"

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	// First lookups
	host, ok := repl.GetString("http.request.remote.host")
	if !ok || host != "192.168.1.100" {
		t.Fatalf("expected remote.host 192.168.1.100, got %q (ok=%t)", host, ok)
	}
	port, ok := repl.GetString("http.request.remote.port")
	if !ok || port != "54321" {
		t.Fatalf("expected remote.port 54321, got %q (ok=%t)", port, ok)
	}
	prefix, ok := repl.GetString("http.request.remote.host/24")
	if !ok || prefix != "192.168.1.0/24" {
		t.Fatalf("expected remote.host/24 192.168.1.0/24, got %q (ok=%t)", prefix, ok)
	}

	localHost, ok := repl.GetString("http.request.local.host")
	if !ok || localHost != "10.0.0.1" {
		t.Fatalf("expected local.host 10.0.0.1, got %q (ok=%t)", localHost, ok)
	}
	localPort, ok := repl.GetString("http.request.local.port")
	if !ok || localPort != "8080" {
		t.Fatalf("expected local.port 8080, got %q (ok=%t)", localPort, ok)
	}
	localAddrStr, ok := repl.GetString("http.request.local")
	if !ok || localAddrStr != "10.0.0.1:8080" {
		t.Fatalf("expected local 10.0.0.1:8080, got %q (ok=%t)", localAddrStr, ok)
	}

	prefixedQuery, ok := repl.GetString("http.request.uri.prefixed_query")
	if !ok || prefixedQuery != "?foo=bar" {
		t.Fatalf("expected uri.prefixed_query ?foo=bar, got %q (ok=%t)", prefixedQuery, ok)
	}
	origPrefixedQuery, ok := repl.GetString("http.request.orig_uri.prefixed_query")
	if !ok || origPrefixedQuery != "?baz=qux" {
		t.Fatalf("expected orig_uri.prefixed_query ?baz=qux, got %q (ok=%t)", origPrefixedQuery, ok)
	}

	// Mutate underlying request fields to verify cached values are retained
	req.RemoteAddr = "1.1.1.1:9999"
	req.URL.RawQuery = "foo=changed"

	host2, _ := repl.GetString("http.request.remote.host")
	if host2 != "192.168.1.100" {
		t.Errorf("expected memoized remote.host 192.168.1.100, got %q", host2)
	}
	port2, _ := repl.GetString("http.request.remote.port")
	if port2 != "54321" {
		t.Errorf("expected memoized remote.port 54321, got %q", port2)
	}
	prefix2, _ := repl.GetString("http.request.remote.host/24")
	if prefix2 != "192.168.1.0/24" {
		t.Errorf("expected memoized remote.host/24 192.168.1.0/24, got %q", prefix2)
	}
	prefixedQuery2, _ := repl.GetString("http.request.uri.prefixed_query")
	if prefixedQuery2 != "?foo=bar" {
		t.Errorf("expected memoized uri.prefixed_query ?foo=bar, got %q", prefixedQuery2)
	}
}

func TestHTTPVarsMemoizationConcurrency(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?a=1&b=2", nil)
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey, localAddr)
	req = req.WithContext(ctx)
	req.RemoteAddr = "10.0.0.5:12345"

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				repl.GetString("http.request.remote.host")
				repl.GetString("http.request.remote.port")
				repl.GetString("http.request.remote.host/16")
				repl.GetString("http.request.local.host")
				repl.GetString("http.request.local.port")
				repl.GetString("http.request.uri.prefixed_query")
			}
		}()
	}
	wg.Wait()
}

func TestHTTPVarsMemoizationAllocations(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?a=1&b=2", nil)
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey, localAddr)
	req = req.WithContext(ctx)
	req.RemoteAddr = "10.0.0.5:12345"

	repl := caddy.NewReplacer()
	addHTTPVarsToReplacer(repl, req, nil)

	// Warm up cache
	repl.Get("http.request.remote.host")
	repl.Get("http.request.remote.port")
	repl.Get("http.request.remote.host/16")
	repl.Get("http.request.local.host")
	repl.Get("http.request.local.port")
	repl.Get("http.request.uri.prefixed_query")

	// Measure allocations on subsequent lookups
	allocsHost := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.remote.host")
	})
	if allocsHost > 0 {
		t.Errorf("expected 0 allocs for remote.host lookup, got %f", allocsHost)
	}

	allocsPort := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.remote.port")
	})
	if allocsPort > 0 {
		t.Errorf("expected 0 allocs for remote.port lookup, got %f", allocsPort)
	}

	allocsPrefix := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.remote.host/16")
	})
	if allocsPrefix > 0 {
		t.Errorf("expected 0 allocs for remote.host/16 lookup, got %f", allocsPrefix)
	}

	allocsLocalHost := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.local.host")
	})
	if allocsLocalHost > 0 {
		t.Errorf("expected 0 allocs for local.host lookup, got %f", allocsLocalHost)
	}

	allocsLocalPort := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.local.port")
	})
	if allocsLocalPort > 0 {
		t.Errorf("expected 0 allocs for local.port lookup, got %f", allocsLocalPort)
	}

	allocsPrefixedQuery := testing.AllocsPerRun(100, func() {
		repl.Get("http.request.uri.prefixed_query")
	})
	if allocsPrefixedQuery > 0 {
		t.Errorf("expected 0 allocs for uri.prefixed_query lookup, got %f", allocsPrefixedQuery)
	}
}

// BenchmarkAddHTTPVarsToReplacer measures the per-request replacer setup, which
// is the common path where the request UUID is never referenced.
func BenchmarkAddHTTPVarsToReplacer(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo?a=b", nil)
	req.Header.Set("User-Agent", "test-agent")
	ctx := context.WithValue(req.Context(), VarsCtxKey, make(map[string]any))
	ctx = context.WithValue(ctx, ExtraLogFieldsCtxKey, new(ExtraLogFields))
	req = req.WithContext(ctx)

	b.ReportAllocs()
	for b.Loop() {
		repl := caddy.NewReplacer()
		addHTTPVarsToReplacer(repl, req, nil)
	}
}

// TestHTTPVarReplacementUUID verifies the lazily-allocated request UUID is
// generated on first access and stays stable across references.
func TestHTTPVarReplacementUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]any))
	ctx = context.WithValue(ctx, ExtraLogFieldsCtxKey, new(ExtraLogFields))
	req = req.WithContext(ctx)
	addHTTPVarsToReplacer(repl, req, nil)

	first, ok := repl.GetString("http.request.uuid")
	if !ok || first == "" {
		t.Fatalf("expected a non-empty uuid, got %q (ok=%t)", first, ok)
	}

	second, _ := repl.GetString("http.request.uuid")
	if first != second {
		t.Errorf("expected stable uuid across references: %q != %q", first, second)
	}
}

// failingBodyReader serves some bytes and then returns a fixed error, to
// exercise the read failure path of the request body placeholders.
type failingBodyReader struct {
	data []byte
	pos  int
	err  error
}

func (b *failingBodyReader) Read(p []byte) (int, error) {
	if b.pos < len(b.data) {
		n := copy(p, b.data[b.pos:])
		b.pos += n
		return n, nil
	}
	return 0, b.err
}

func (b *failingBodyReader) Close() error { return nil }

// TestRequestBodyPlaceholderErrorScoping verifies that only a max_size-driven
// handler error from the request body read becomes a RequestBodyLimitError,
// while every other error keeps the placeholder's old ignore-and-truncate
// behavior.
func TestRequestBodyPlaceholderErrorScoping(t *testing.T) {
	maxBytes := &http.MaxBytesError{Limit: 10}
	for _, tc := range []struct {
		name       string
		readErr    error
		wantMarker bool
	}{
		{name: "max_size handler error becomes the marker", readErr: HandlerError{Err: maxBytes, StatusCode: http.StatusRequestEntityTooLarge}, wantMarker: true},
		{name: "unrelated handler error keeps old behavior", readErr: HandlerError{Err: errors.New("boom"), StatusCode: http.StatusInternalServerError}},
		{name: "raw max bytes error keeps old behavior", readErr: maxBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Body = &failingBodyReader{data: []byte("abc"), err: tc.readErr}

			body, err := readRequestBodyForPlaceholder(req)

			if !tc.wantMarker {
				if err != nil {
					t.Fatalf("unrelated errors must be ignored like before but got %v", err)
				}
				if string(body) != "abc" {
					t.Errorf("expected the truncated prefix %q but got %q", "abc", body)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the body limit marker but got none")
			}
			var marker RequestBodyLimitError
			if !errors.As(err, &marker) {
				t.Fatalf("expected RequestBodyLimitError but got %T", err)
			}
			var handlerErr HandlerError
			if errors.As(err, &handlerErr) {
				t.Error("the marker must not be detectable as a HandlerError")
			}
			if marker.StatusCode() != http.StatusRequestEntityTooLarge {
				t.Errorf("expected status 413 but got %d", marker.StatusCode())
			}
			var maxErr *http.MaxBytesError
			if !errors.As(err, &maxErr) {
				t.Error("the marker must unwrap to the MaxBytesError")
			}
		})
	}
}
