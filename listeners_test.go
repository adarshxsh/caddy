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
	"context"
	"crypto/tls"
	"net"
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

	sqs := newSharedQUICState()
	ctx1, cancel1 := sqs.addState(initialConfig, nil)
	_ = ctx1

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

	_, cancel2 := sqs.addState(updatedConfig, nil)

	keys, err = sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting updated ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, updatedKeys) {
		t.Fatalf("unexpected updated ECH keys: got %#v, want %#v", keys, updatedKeys)
	}

	cancel2(nil)

	keys, err = sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting restored ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, initialKeys) {
		t.Fatalf("unexpected restored ECH keys: got %#v, want %#v", keys, initialKeys)
	}

	cancel1(nil)
}

func TestSharedQUICState0RTTPolicy(t *testing.T) {
	sqs := newSharedQUICState()

	// Initially with no bindings, default Allow0RTT is true
	qc, err := sqs.getQUICConfigForClient(nil)
	if err != nil || !qc.Allow0RTT {
		t.Fatalf("expected initial Allow0RTT to be true, got %v, err: %v", qc.Allow0RTT, err)
	}

	// Add server 1: allows 0-RTT (default nil)
	tlsConf1 := &tls.Config{}
	_, cancel1 := sqs.addState(tlsConf1, nil)
	qc, _ = sqs.getQUICConfigForClient(nil)
	if !qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be true after adding server 1")
	}

	// Add server 2: explicitly disables 0-RTT
	allowFalse := false
	tlsConf2 := &tls.Config{}
	_, cancel2 := sqs.addState(tlsConf2, &allowFalse)
	qc, _ = sqs.getQUICConfigForClient(nil)
	if qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be false after adding server 2 with allow_0rtt: false")
	}

	// Add server 3: explicitly allows 0-RTT
	allowTrue := true
	tlsConf3 := &tls.Config{}
	_, cancel3 := sqs.addState(tlsConf3, &allowTrue)
	qc, _ = sqs.getQUICConfigForClient(nil)
	if qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to remain false while server 2 is active")
	}

	// Stop server 2 (which disabled 0-RTT)
	cancel2(nil)
	qc, _ = sqs.getQUICConfigForClient(nil)
	if !qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be restored to true after stopping server 2")
	}

	// Cleanup remaining
	cancel1(nil)
	cancel3(nil)
}

func TestListenQUIC0RTTMultiServerAndReload(t *testing.T) {
	// Find an available UDP port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	addrStr := pc.LocalAddr().String()
	pc.Close()

	na, err := ParseNetworkAddress("udp/" + addrStr)
	if err != nil {
		t.Fatalf("unexpected error parsing address: %v", err)
	}

	tlsConf1 := &tls.Config{}
	ctx := context.Background()

	// Server 1 binds with default 0-RTT allowed
	ln1, err := na.ListenQUIC(ctx, 0, net.ListenConfig{}, tlsConf1, nil, nil)
	if err != nil {
		t.Fatalf("ListenQUIC for server 1 failed: %v", err)
	}
	defer ln1.Close()

	fq1, ok := ln1.(*fakeCloseQuicListener)
	if !ok {
		t.Fatalf("expected fakeCloseQuicListener, got %T", ln1)
	}

	qc, _ := fq1.sqs.getQUICConfigForClient(nil)
	if !qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be true for server 1")
	}

	// Server 2 binds to shared socket and disables 0-RTT
	allowFalse := false
	tlsConf2 := &tls.Config{}
	ln2, err := na.ListenQUIC(ctx, 0, net.ListenConfig{}, tlsConf2, nil, &allowFalse)
	if err != nil {
		t.Fatalf("ListenQUIC for server 2 failed: %v", err)
	}

	qc, _ = fq1.sqs.getQUICConfigForClient(nil)
	if qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be false after secondary server bound with allow_0rtt: false")
	}

	// Reload scenario: Server 2 reloads and enables 0-RTT
	allowTrue := true
	tlsConf2New := &tls.Config{}
	ln2New, err := na.ListenQUIC(ctx, 0, net.ListenConfig{}, tlsConf2New, nil, &allowTrue)
	if err != nil {
		t.Fatalf("ListenQUIC for reloaded server 2 failed: %v", err)
	}

	// Old server 2 closes
	if err := ln2.Close(); err != nil {
		t.Fatalf("closing old server 2 failed: %v", err)
	}

	qc, _ = fq1.sqs.getQUICConfigForClient(nil)
	if !qc.Allow0RTT {
		t.Fatalf("expected Allow0RTT to be restored to true after old server 2 closed")
	}

	ln2New.Close()
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
