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
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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

func TestSharedQUICStateGetConfigForClient_KeyRotation(t *testing.T) {
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}

	var key1, key2 [32]byte
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	policyConfig1 := &tls.Config{
		ServerName: "example.com",
	}
	policyConfig1.SetSessionTicketKeys([][32]byte{key1})

	masterConfig1 := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return policyConfig1, nil
		},
	}

	sqs := newSharedQUICState(masterConfig1)

	// Step 1: Initial GetConfigForClient should return policyConfig1
	cfg, err := sqs.getConfigForClient(hello)
	if err != nil {
		t.Fatalf("getting initial config for client: %v", err)
	}
	if cfg != policyConfig1 {
		t.Fatalf("expected policyConfig1, got %v", cfg)
	}

	// Step 2: Rotate ticket keys on policyConfig1 (as SessionTicketService does)
	policyConfig1.SetSessionTicketKeys([][32]byte{key2, key1})

	// Step 3: GetConfigForClient still delegates to policyConfig1, which now has updated ticket keys
	cfg, err = sqs.getConfigForClient(hello)
	if err != nil {
		t.Fatalf("getting updated config for client: %v", err)
	}
	if cfg != policyConfig1 {
		t.Fatalf("expected policyConfig1, got %v", cfg)
	}

	// Step 4: Verify state transition across configuration reload
	policyConfig2 := &tls.Config{
		ServerName: "example.com",
	}
	policyConfig2.SetSessionTicketKeys([][32]byte{key2})

	masterConfig2 := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return policyConfig2, nil
		},
	}

	_, cancel := sqs.addState(masterConfig2)
	sqs.rmu.Lock()
	sqs.activeTlsConf = masterConfig2
	sqs.rmu.Unlock()

	cfg, err = sqs.getConfigForClient(hello)
	if err != nil {
		t.Fatalf("getting config after state reload: %v", err)
	}
	if cfg != policyConfig2 {
		t.Fatalf("expected policyConfig2 after state transition, got %v", cfg)
	}

	// Step 5: Cancel active state and confirm fallback to initial config
	cancel(nil)

	cfg, err = sqs.getConfigForClient(hello)
	if err != nil {
		t.Fatalf("getting config after cancellation: %v", err)
	}
	if cfg != policyConfig1 {
		t.Fatalf("expected restored policyConfig1, got %v", cfg)
	}
}

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func TestQUIC_0RTT_SessionResumption_KeyRotation(t *testing.T) {
	cert := generateTestCert(t)

	var key1, key2, key3 [32]byte
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}
	if _, err := rand.Read(key3[:]); err != nil {
		t.Fatalf("failed to generate key3: %v", err)
	}

	policyConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	policyConfig.SetSessionTicketKeys([][32]byte{key1})

	masterConfig := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			return policyConfig, nil
		},
	}

	na := NetworkAddress{
		Network:   "udp",
		Host:      "127.0.0.1",
		StartPort: 0,
		EndPort:   0,
	}
	allow0RTT := true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ql, err := na.ListenQUIC(ctx, 0, net.ListenConfig{}, masterConfig, nil, &allow0RTT)
	if err != nil {
		t.Fatalf("ListenQUIC failed: %v", err)
	}
	defer ql.Close()
	defer ql.Close()

	// Accept QUIC connections and handle streams in background
	go func() {
		for {
			conn, err := ql.Accept(ctx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					stream, err := c.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func(s *quic.Stream) {
						defer s.Close()
						buf := make([]byte, 100)
						n, _ := s.Read(buf)
						if n > 0 {
							_, _ = s.Write(buf[:n])
						}
					}(stream)
				}
			}(conn)
		}
	}()

	serverAddr := ql.Addr().String()

	clientSessionCache := tls.NewLRUClientSessionCache(100)
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ClientSessionCache: clientSessionCache,
	}

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen on client UDP socket: %v", err)
	}
	defer clientConn.Close()

	tr := &quic.Transport{
		Conn: clientConn,
	}
	defer tr.Close()

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to resolve server address: %v", err)
	}

	quicConf := &quic.Config{
		Allow0RTT: true,
	}

	// Step 1: Initial connection (1-RTT) to receive and cache session ticket
	conn1, err := tr.Dial(ctx, udpAddr, clientTLS, quicConf)
	if err != nil {
		t.Fatalf("Initial QUIC connection failed: %v", err)
	}
	str1, err := conn1.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync on conn1 failed: %v", err)
	}
	if _, err := str1.Write([]byte("ping")); err != nil {
		t.Fatalf("Write on conn1 failed: %v", err)
	}
	_ = str1.Close()
	buf := make([]byte, 100)
	n, err := io.ReadFull(str1, buf[:4])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("Read on conn1 failed: %v (n=%d)", err, n)
	}

	// Wait briefly for Session Ticket frame processing before closing
	time.Sleep(100 * time.Millisecond)
	_ = conn1.CloseWithError(0, "done")

	// Step 2: Rotate session ticket keys on policyConfig (key2 is primary, key1 is retained)
	policyConfig.SetSessionTicketKeys([][32]byte{key2, key1})

	// Step 3: Connection 2 - 0-RTT session resumption across key rotation cycle
	conn2, err := tr.DialEarly(ctx, udpAddr, clientTLS, quicConf)
	if err != nil {
		t.Fatalf("Resumed QUIC connection 2 failed: %v", err)
	}

	str2, err := conn2.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync on conn2 failed: %v", err)
	}
	if _, err := str2.Write([]byte("0rtt-data")); err != nil {
		t.Fatalf("Write on conn2 failed: %v", err)
	}
	_ = str2.Close()
	n, err = io.ReadFull(str2, buf[:9])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("Read on conn2 failed: %v (n=%d)", err, n)
	}

	if !conn2.ConnectionState().TLS.DidResume {
		t.Errorf("Expected session resumption on conn2 after key rotation, but DidResume was false")
	}

	_ = conn2.CloseWithError(0, "done")

	// Step 4: Second key rotation cycle (key3 is primary, key2 and key1 retained)
	policyConfig.SetSessionTicketKeys([][32]byte{key3, key2, key1})

	// Step 5: Connection 3 - 0-RTT session resumption across second key rotation
	conn3, err := tr.DialEarly(ctx, udpAddr, clientTLS, quicConf)
	if err != nil {
		t.Fatalf("Resumed QUIC connection 3 failed: %v", err)
	}

	str3, err := conn3.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync on conn3 failed: %v", err)
	}
	if _, err := str3.Write([]byte("0rtt-data-2")); err != nil {
		t.Fatalf("Write on conn3 failed: %v", err)
	}
	_ = str3.Close()
	n, err = io.ReadFull(str3, buf[:11])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("Read on conn3 failed: %v (n=%d)", err, n)
	}

	if !conn3.ConnectionState().TLS.DidResume {
		t.Errorf("Expected session resumption on conn3 after second key rotation, but DidResume was false")
	}

	_ = conn3.CloseWithError(0, "done")
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
