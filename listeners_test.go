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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

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
	sqs.rmu.Lock()
	sqs.activeTlsConf = updatedConfig
	sqs.rmu.Unlock()

	keys, err = sqs.getEncryptedClientHelloKeys(hello)
	if err != nil {
		t.Fatalf("getting updated ECH keys: %v", err)
	}
	if !reflect.DeepEqual(keys, updatedKeys) {
		t.Fatalf("unexpected updated ECH keys: got %#v, want %#v", keys, updatedKeys)
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

// mockSessionTicketService simulates SessionTicketService key rotation across registered connection policy tls.Configs.
type mockSessionTicketService struct {
	mu      sync.Mutex
	configs map[*tls.Config]struct{}
}

func newMockSessionTicketService() *mockSessionTicketService {
	return &mockSessionTicketService{
		configs: make(map[*tls.Config]struct{}),
	}
}

func (s *mockSessionTicketService) Register(cfg *tls.Config, initialKeys [][32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.SetSessionTicketKeys(initialKeys)
	s.configs[cfg] = struct{}{}
}

func (s *mockSessionTicketService) RotateKeys(newKeys [][32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for cfg := range s.configs {
		cfg.SetSessionTicketKeys(newKeys)
	}
}

func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("generating serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Caddy Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return tlsCert, certPool
}

func TestQUICListenerSessionTicketRotation(t *testing.T) {
	tlsCert, certPool := generateTestCert(t)

	var key1, key2, key3 [32]byte
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatalf("key1: %v", err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		t.Fatalf("key2: %v", err)
	}
	if _, err := rand.Read(key3[:]); err != nil {
		t.Fatalf("key3: %v", err)
	}

	stekService := newMockSessionTicketService()

	policyTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"},
	}
	stekService.Register(policyTLSConfig, [][32]byte{key1})

	// Delegate GetConfigForClient to policyTLSConfig (simulating connection policy selection)
	outerTLSConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return policyTLSConfig, nil
		},
	}

	allow0RTT := true
	na := NetworkAddress{
		Network: "udp",
		Host:    "127.0.0.1",
	}
	earlyLn, err := na.ListenQUIC(context.Background(), 0, net.ListenConfig{}, outerTLSConfig, nil, &allow0RTT)
	if err != nil {
		t.Fatalf("ListenQUIC failed: %v", err)
	}
	defer func() {
		_ = earlyLn.Close()
		_ = earlyLn.Close()
	}()

	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()

	go func() {
		for {
			conn, err := earlyLn.Accept(serverCtx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				str, err := c.AcceptStream(serverCtx)
				if err == nil {
					b := make([]byte, 4)
					_, _ = io.ReadFull(str, b)
					_, _ = str.Write([]byte("pong"))
				}
			}(conn)
		}
	}()

	serverAddrStr := earlyLn.Addr().String()
	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	clientSessionCache := tls.NewLRUClientSessionCache(10)
	clientTLSConfig := &tls.Config{
		RootCAs:            certPool,
		ServerName:         "localhost",
		NextProtos:         []string{"h3"},
		ClientSessionCache: clientSessionCache,
	}

	// 1st Handshake: Obtain session ticket encrypted with key1
	udpConn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP 1: %v", err)
	}
	defer udpConn1.Close()

	tr1 := &quic.Transport{Conn: udpConn1}
	defer tr1.Close()

	dialCtx1, dialCancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel1()

	conn1, err := tr1.DialEarly(dialCtx1, remoteAddr, clientTLSConfig, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("DialEarly 1 failed: %v", err)
	}

	str1, err := conn1.OpenStreamSync(dialCtx1)
	if err != nil {
		t.Fatalf("OpenStreamSync 1 failed: %v", err)
	}
	if _, err := str1.Write([]byte("ping")); err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(str1, buf); err != nil {
		t.Fatalf("Read 1 failed: %v", err)
	}

	select {
	case <-conn1.HandshakeComplete():
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handshake 1 complete")
	}

	// Wait briefly for ticket to land in clientSessionCache
	time.Sleep(150 * time.Millisecond)
	_ = conn1.CloseWithError(0, "")

	// 2. Rotate keys: key2 is new primary, key1 is secondary
	stekService.RotateKeys([][32]byte{key2, key1})
	time.Sleep(50 * time.Millisecond)

	// 2nd Handshake: Resume session using rotated key (key1 is secondary on policyTLSConfig)
	udpConn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP 2: %v", err)
	}
	defer udpConn2.Close()

	tr2 := &quic.Transport{Conn: udpConn2}
	defer tr2.Close()

	dialCtx2, dialCancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel2()

	conn2, err := tr2.DialEarly(dialCtx2, remoteAddr, clientTLSConfig, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("DialEarly 2 failed: %v", err)
	}

	select {
	case <-conn2.HandshakeComplete():
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handshake 2 complete")
	}

	cs2 := conn2.ConnectionState()
	if !cs2.TLS.DidResume {
		t.Errorf("Handshake 2 failed to resume session after key rotation (DidResume=false)")
	}
	_ = conn2.CloseWithError(0, "")

	// 3. Rotate keys again: evict key1, leaving only key3 and key2
	stekService.RotateKeys([][32]byte{key3, key2})
	time.Sleep(50 * time.Millisecond)

	// 3rd Handshake: Verification that ticket encrypted with key1 fails decryption after eviction
	udpConn3, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP 3: %v", err)
	}
	defer udpConn3.Close()

	tr3 := &quic.Transport{Conn: udpConn3}
	defer tr3.Close()

	dialCtx3, dialCancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel3()

	conn3, err := tr3.DialEarly(dialCtx3, remoteAddr, clientTLSConfig, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("DialEarly 3 failed: %v", err)
	}

	select {
	case <-conn3.HandshakeComplete():
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handshake 3 complete")
	}

	cs3 := conn3.ConnectionState()
	if cs3.TLS.DidResume {
		t.Errorf("Handshake 3 unexpectedly resumed session after ticket key eviction")
	}
	_ = conn3.CloseWithError(0, "")
}
