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

package caddy

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/internal"
)

func TestSplitNetworkAddress(t *testing.T) {
	for i, tc := range []struct {
		input         string
		expectNetwork string
		expectHost    string
		expectPort    string
		expectErr     bool
	}{
		{
			input:      "",
			expectHost: "",
		},
		{
			input:      "foo",
			expectHost: "foo",
		},
		{
			input: ":", // empty host & empty port
		},
		{
			input:      "::",
			expectHost: "::",
		},
		{
			input:      "[::]",
			expectHost: "::",
		},
		{
			input:      ":1234",
			expectPort: "1234",
		},
		{
			input:      "foo:1234",
			expectHost: "foo",
			expectPort: "1234",
		},
		{
			input:      "foo:1234-5678",
			expectHost: "foo",
			expectPort: "1234-5678",
		},
		{
			input:         "udp/foo:1234",
			expectNetwork: "udp",
			expectHost:    "foo",
			expectPort:    "1234",
		},
		{
			input:         "tcp6/foo:1234-5678",
			expectNetwork: "tcp6",
			expectHost:    "foo",
			expectPort:    "1234-5678",
		},
		{
			input:         "udp/",
			expectNetwork: "udp",
			expectHost:    "",
		},
		{
			input:         "unix//foo/bar",
			expectNetwork: "unix",
			expectHost:    "/foo/bar",
		},
		{
			input:         "unixgram//foo/bar",
			expectNetwork: "unixgram",
			expectHost:    "/foo/bar",
		},
		{
			input:         "unixpacket//foo/bar",
			expectNetwork: "unixpacket",
			expectHost:    "/foo/bar",
		},
	} {
		actualNetwork, actualHost, actualPort, err := SplitNetworkAddress(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got %v", i, err)
		}
		if actualNetwork != tc.expectNetwork {
			t.Errorf("Test %d: Expected network '%s' but got '%s'", i, tc.expectNetwork, actualNetwork)
		}
		if actualHost != tc.expectHost {
			t.Errorf("Test %d: Expected host '%s' but got '%s'", i, tc.expectHost, actualHost)
		}
		if actualPort != tc.expectPort {
			t.Errorf("Test %d: Expected port '%s' but got '%s'", i, tc.expectPort, actualPort)
		}
	}
}

func TestJoinNetworkAddress(t *testing.T) {
	for i, tc := range []struct {
		network, host, port string
		expect              string
	}{
		{
			network: "", host: "", port: "",
			expect: "",
		},
		{
			network: "tcp", host: "", port: "",
			expect: "tcp/",
		},
		{
			network: "", host: "foo", port: "",
			expect: "foo",
		},
		{
			network: "", host: "", port: "1234",
			expect: ":1234",
		},
		{
			network: "", host: "", port: "1234-5678",
			expect: ":1234-5678",
		},
		{
			network: "", host: "foo", port: "1234",
			expect: "foo:1234",
		},
		{
			network: "udp", host: "foo", port: "1234",
			expect: "udp/foo:1234",
		},
		{
			network: "udp", host: "", port: "1234",
			expect: "udp/:1234",
		},
		{
			network: "unix", host: "/foo/bar", port: "",
			expect: "unix//foo/bar",
		},
		{
			network: "unix", host: "/foo/bar", port: "0",
			expect: "unix//foo/bar",
		},
		{
			network: "unix", host: "/foo/bar", port: "1234",
			expect: "unix//foo/bar",
		},
		{
			network: "", host: "::1", port: "1234",
			expect: "[::1]:1234",
		},
	} {
		actual := JoinNetworkAddress(tc.network, tc.host, tc.port)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, tc.expect, actual)
		}
	}
}

func TestSharedQUICStateGetEncryptedClientHelloKeys(t *testing.T) {
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	initialKeys := []tls.EncryptedClientHelloKey{{Config: []byte("initial"), PrivateKey: []byte("initial-key")}}
	updatedKeys := []tls.EncryptedClientHelloKey{{Config: []byte("updated"), PrivateKey: []byte("updated-key")}}

	initialConfig := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, nil
		},
		GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return initialKeys, nil
		},
	}

	sqs := newSharedQUICState(initialConfig)

	keys, err := sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting initial ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, initialKeys) {
		t.Fatalf("unexpected initial ECH keys: got %#v, want %#v", keys, initialKeys)
	}

	updatedConfig := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, nil
		},
		GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return updatedKeys, nil
		},
	}

	_, cancel := sqs.addState(updatedConfig)

	expectedAggregated := append([]tls.EncryptedClientHelloKey{}, updatedKeys...)
	expectedAggregated = append(expectedAggregated, initialKeys...)

	keys, err = sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting updated ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, expectedAggregated) {
		t.Fatalf("unexpected updated ECH keys: got %#v, want %#v", keys, expectedAggregated)
	}

	cancel(nil)

	keys, err = sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting restored ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, initialKeys) {
		t.Fatalf("unexpected restored ECH keys: got %#v, want %#v", keys, initialKeys)
	}
}

func TestSharedQUICStateMultiConfigDispatch(t *testing.T) {
	tc1Target := &tls.Config{MinVersion: tls.VersionTLS13}
	tc2Target := &tls.Config{MinVersion: tls.VersionTLS12}

	tc1 := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			if ch.ServerName == "domain-a.com" {
				return tc1Target, nil
			}
			return nil, fmt.Errorf("domain %s not matched on tc1", ch.ServerName)
		},
	}

	sqs := newSharedQUICState(tc1)

	// Test initial single config
	got, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "domain-a.com"})
	if err != nil || got != tc1Target {
		t.Fatalf("expected tc1Target, got %v, err: %v", got, err)
	}

	// Register second config
	tc2 := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			if ch.ServerName == "domain-b.com" {
				return tc2Target, nil
			}
			return nil, fmt.Errorf("domain %s not matched on tc2", ch.ServerName)
		},
	}

	_, cancel2 := sqs.addState(tc2)

	// addState promotes tc2 to activeTlsConf
	if sqs.activeTlsConf != tc2 {
		t.Fatalf("expected activeTlsConf to be promoted to tc2, got %v", sqs.activeTlsConf)
	}

	// Request for domain-b.com matches activeTlsConf (tc2) directly
	gotB, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "domain-b.com"})
	if err != nil || gotB != tc2Target {
		t.Fatalf("expected tc2Target for domain-b.com, got %v, err: %v", gotB, err)
	}

	// Request for domain-a.com fails activeTlsConf (tc2) and falls back to tc1
	gotA, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "domain-a.com"})
	if err != nil || gotA != tc1Target {
		t.Fatalf("expected fallback to tc1Target for domain-a.com, got %v, err: %v", gotA, err)
	}

	// Request for unknown domain fails across all configs
	gotUnknown, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "unknown.com"})
	if err == nil || gotUnknown != nil {
		t.Fatalf("expected error for unknown domain, got config %v, err: %v", gotUnknown, err)
	}

	// Cancel tc2, verifying promotion fallback
	cancel2(nil)

	if sqs.activeTlsConf != tc1 {
		t.Fatalf("expected activeTlsConf to revert to tc1 after cancel, got %v", sqs.activeTlsConf)
	}

	gotA2, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "domain-a.com"})
	if err != nil || gotA2 != tc1Target {
		t.Fatalf("expected tc1Target for domain-a.com after cancel, got %v, err: %v", gotA2, err)
	}
}

func TestSharedQUICStateAddStatePromotion(t *testing.T) {
	tc1 := &tls.Config{MinVersion: tls.VersionTLS12}
	tc2 := &tls.Config{MinVersion: tls.VersionTLS13}

	sqs := newSharedQUICState(tc1)
	if sqs.activeTlsConf != tc1 {
		t.Fatalf("expected activeTlsConf to be tc1, got %v", sqs.activeTlsConf)
	}

	sqs.addState(tc2)
	if sqs.activeTlsConf != tc2 {
		t.Fatalf("expected activeTlsConf to be promoted to tc2, got %v", sqs.activeTlsConf)
	}

	// Re-adding tc1 should re-promote tc1 to activeTlsConf
	sqs.addState(tc1)
	if sqs.activeTlsConf != tc1 {
		t.Fatalf("expected activeTlsConf to be re-promoted to tc1, got %v", sqs.activeTlsConf)
	}
}

func TestSharedQUICStateNilGetConfigForClient(t *testing.T) {
	tcStatic := &tls.Config{MinVersion: tls.VersionTLS13}
	sqs := newSharedQUICState(tcStatic)

	got, err := sqs.getConfigForClient(&tls.ClientHelloInfo{ServerName: "any.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != tcStatic {
		t.Fatalf("expected static config %v, got %v", tcStatic, got)
	}
}

func TestSharedQUICStateGetEncryptedClientHelloKeysError(t *testing.T) {
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	expectedErr := fmt.Errorf("failed to fetch ECH keys")

	tc := &tls.Config{
		GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return nil, expectedErr
		},
	}

	sqs := newSharedQUICState(tc)
	keys, err := sqs.getEncryptedClientHelloKeys(hello)
	if err == nil {
		t.Fatalf("expected error, got keys: %v", keys)
	}
	if err.Error() != expectedErr.Error() {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
}

func TestParseNetworkAddress(t *testing.T) {
	for i, tc := range []struct {
		input          string
		defaultNetwork string
		defaultPort    uint
		expectAddr     NetworkAddress
		expectErr      bool
	}{
		{
			input:      "",
			expectAddr: NetworkAddress{},
		},
		{
			input:          ":",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network: "udp",
			},
		},
		{
			input:          "[::]",
			defaultNetwork: "udp",
			defaultPort:    53,
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "::",
				StartPort: 53,
				EndPort:   53,
			},
		},
		{
			input:          ":1234",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "udp/:1234",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "tcp6/:1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp6",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "tcp4/localhost:1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp4",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "unix//foo/bar",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network: "unix",
				Host:    "/foo/bar",
			},
		},
		{
			input:          "localhost:1234-1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "localhost:2-1",
			defaultNetwork: "tcp",
			expectErr:      true,
		},
		{
			input:          "localhost:0",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 0,
				EndPort:   0,
			},
		},
		{
			input:          "localhost:1-999999999999",
			defaultNetwork: "tcp",
			expectErr:      true,
		},
	} {
		actualAddr, err := ParseNetworkAddressWithDefaults(tc.input, tc.defaultNetwork, tc.defaultPort)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}

		if actualAddr.Network != tc.expectAddr.Network {
			t.Errorf("Test %d: Expected network '%v' but got '%v'", i, tc.expectAddr, actualAddr)
		}
		if !reflect.DeepEqual(tc.expectAddr, actualAddr) {
			t.Errorf("Test %d: Expected addresses %v but got %v", i, tc.expectAddr, actualAddr)
		}
	}
}

func TestParseNetworkAddressWithDefaults(t *testing.T) {
	for i, tc := range []struct {
		input          string
		defaultNetwork string
		defaultPort    uint
		expectAddr     NetworkAddress
		expectErr      bool
	}{
		{
			input:      "",
			expectAddr: NetworkAddress{},
		},
		{
			input:          ":",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network: "udp",
			},
		},
		{
			input:          "[::]",
			defaultNetwork: "udp",
			defaultPort:    53,
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "::",
				StartPort: 53,
				EndPort:   53,
			},
		},
		{
			input:          ":1234",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "udp/:1234",
			defaultNetwork: "udp",
			expectAddr: NetworkAddress{
				Network:   "udp",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "tcp6/:1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp6",
				Host:      "",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "tcp4/localhost:1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp4",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "unix//foo/bar",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network: "unix",
				Host:    "/foo/bar",
			},
		},
		{
			input:          "localhost:1234-1234",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1234,
			},
		},
		{
			input:          "localhost:2-1",
			defaultNetwork: "tcp",
			expectErr:      true,
		},
		{
			input:          "localhost:0",
			defaultNetwork: "tcp",
			expectAddr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 0,
				EndPort:   0,
			},
		},
		{
			input:          "localhost:1-999999999999",
			defaultNetwork: "tcp",
			expectErr:      true,
		},
	} {
		actualAddr, err := ParseNetworkAddressWithDefaults(tc.input, tc.defaultNetwork, tc.defaultPort)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}

		if actualAddr.Network != tc.expectAddr.Network {
			t.Errorf("Test %d: Expected network '%v' but got '%v'", i, tc.expectAddr, actualAddr)
		}
		if !reflect.DeepEqual(tc.expectAddr, actualAddr) {
			t.Errorf("Test %d: Expected addresses %v but got %v", i, tc.expectAddr, actualAddr)
		}
	}
}

func TestJoinHostPort(t *testing.T) {
	for i, tc := range []struct {
		pa     NetworkAddress
		offset uint
		expect string
	}{
		{
			pa: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1234,
			},
			expect: "localhost:1234",
		},
		{
			pa: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1235,
			},
			expect: "localhost:1234",
		},
		{
			pa: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 1234,
				EndPort:   1235,
			},
			offset: 1,
			expect: "localhost:1235",
		},
		{
			pa: NetworkAddress{
				Network: "unix",
				Host:    "/run/php/php7.3-fpm.sock",
			},
			expect: "/run/php/php7.3-fpm.sock",
		},
	} {
		actual := tc.pa.JoinHostPort(tc.offset)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, tc.expect, actual)
		}
	}
}

func TestExpand(t *testing.T) {
	for i, tc := range []struct {
		input  NetworkAddress
		expect []NetworkAddress
	}{
		{
			input: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 2000,
				EndPort:   2000,
			},
			expect: []NetworkAddress{
				{
					Network:   "tcp",
					Host:      "localhost",
					StartPort: 2000,
					EndPort:   2000,
				},
			},
		},
		{
			input: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 2000,
				EndPort:   2002,
			},
			expect: []NetworkAddress{
				{
					Network:   "tcp",
					Host:      "localhost",
					StartPort: 2000,
					EndPort:   2000,
				},
				{
					Network:   "tcp",
					Host:      "localhost",
					StartPort: 2001,
					EndPort:   2001,
				},
				{
					Network:   "tcp",
					Host:      "localhost",
					StartPort: 2002,
					EndPort:   2002,
				},
			},
		},
		{
			input: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 2000,
				EndPort:   1999,
			},
			expect: []NetworkAddress{},
		},
		{
			input: NetworkAddress{
				Network:   "unix",
				Host:      "/foo/bar",
				StartPort: 0,
				EndPort:   0,
			},
			expect: []NetworkAddress{
				{
					Network:   "unix",
					Host:      "/foo/bar",
					StartPort: 0,
					EndPort:   0,
				},
			},
		},
	} {
		actual := tc.input.Expand()
		if !reflect.DeepEqual(actual, tc.expect) {
			t.Errorf("Test %d: Expected %+v but got %+v", i, tc.expect, actual)
		}
	}
}

func TestSplitUnixSocketPermissionsBits(t *testing.T) {
	for i, tc := range []struct {
		input          string
		expectNetwork  string
		expectPath     string
		expectFileMode string
		expectErr      bool
	}{
		{
			input:          "./foo.socket",
			expectPath:     "./foo.socket",
			expectFileMode: "--w-------",
		},
		{
			input:          `.\relative\path.socket`,
			expectPath:     `.\relative\path.socket`,
			expectFileMode: "--w-------",
		},
		{
			// literal colon in resulting address
			// and defaulting to 0200 bits
			input:          "./foo.socket:0666",
			expectPath:     "./foo.socket:0666",
			expectFileMode: "--w-------",
		},
		{
			input:          "./foo.socket|0220",
			expectPath:     "./foo.socket",
			expectFileMode: "--w--w----",
		},
		{
			input:          "/var/run/foo|222",
			expectPath:     "/var/run/foo",
			expectFileMode: "--w--w--w-",
		},
		{
			input:          "./foo.socket|0660",
			expectPath:     "./foo.socket",
			expectFileMode: "-rw-rw----",
		},
		{
			input:          "./foo.socket|0666",
			expectPath:     "./foo.socket",
			expectFileMode: "-rw-rw-rw-",
		},
		{
			input:          "/var/run/foo|666",
			expectPath:     "/var/run/foo",
			expectFileMode: "-rw-rw-rw-",
		},
		{
			input:          `c:\absolute\path.socket|220`,
			expectPath:     `c:\absolute\path.socket`,
			expectFileMode: "--w--w----",
		},
		{
			// symbolic permission representation is not supported for now
			input:     "./foo.socket|u=rw,g=rw,o=rw",
			expectErr: true,
		},
		{
			// octal (base-8) permission representation has to be between
			// `0` for no read, no write, no exec (`---`) and
			// `7` for read (4), write (2), exec (1) (`rwx` => `4+2+1 = 7`)
			input:     "./foo.socket|888",
			expectErr: true,
		},
		{
			// too many colons in address
			input:     "./foo.socket|123456|0660",
			expectErr: true,
		},
		{
			// owner is missing write perms
			input:     "./foo.socket|0522",
			expectErr: true,
		},
	} {
		actualPath, actualFileMode, err := internal.SplitUnixSocketPermissionsBits(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}
		if actualPath != tc.expectPath {
			t.Errorf("Test %d: Expected path '%s' but got '%s'", i, tc.expectPath, actualPath)
		}
		// fileMode.Perm().String() parses 0 to "----------"
		if !tc.expectErr && actualFileMode.Perm().String() != tc.expectFileMode {
			t.Errorf("Test %d: Expected perms '%s' but got '%s'", i, tc.expectFileMode, actualFileMode.Perm().String())
		}
	}
}
