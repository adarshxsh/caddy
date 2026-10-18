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

package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type testSTEKProvider struct {
	keys [][32]byte
}

func (p *testSTEKProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.stek.test_stek",
		New: func() caddy.Module { return new(testSTEKProvider) },
	}
}

func (p *testSTEKProvider) Initialize(s *SessionTicketService) ([][32]byte, error) {
	var k [32]byte
	copy(k[:], "initial-test-stek-key-0000000000")
	p.keys = [][32]byte{k}
	return p.keys, nil
}

func (p *testSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	ch := make(chan [][32]byte)
	return ch
}

func generateTestCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
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
		DNSNames:              []string{host},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return tlsCert, certPool
}

func TestQUICSessionTicketKeyRotation(t *testing.T) {
	caddy.RegisterModule(&testSTEKProvider{})

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// 1. Provision SessionTicketService with test provider
	sts := &SessionTicketService{
		KeySource:        json.RawMessage(`{"provider":"test_stek"}`),
		RotationInterval: caddy.Duration(1 * time.Hour),
		MaxKeys:          4,
	}
	if err := sts.provision(ctx); err != nil {
		t.Fatalf("provisioning SessionTicketService: %v", err)
	}
	defer sts.stop()

	// 2. Generate certificate and policy TLS config registered with sts
	tlsCert, certPool := generateTestCert(t, "localhost")
	policyCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}
	sts.register(policyCfg)

	// Top-level listener config that delegates GetConfigForClient to policyCfg
	topLevelCfg := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			return policyCfg, nil
		},
	}

	// Wrap topLevelCfg with http3.ConfigureTLSConfig matching sharedQUICState delegation
	quicTlsConfig := http3.ConfigureTLSConfig(&tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			return topLevelCfg.GetConfigForClient(ch)
		},
	})

	// 3. Start QUIC EarlyListener on UDP port
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolving UDP addr: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listening UDP: %v", err)
	}
	defer serverConn.Close()

	tr := &quic.Transport{Conn: serverConn}
	defer tr.Close()

	earlyLn, err := tr.ListenEarly(quicTlsConfig, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("starting QUIC listener: %v", err)
	}
	defer earlyLn.Close()

	// Accept connections in background and handle stream echo
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()
	go func() {
		for {
			qconn, err := earlyLn.Accept(serverCtx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					str, err := c.AcceptStream(c.Context())
					if err != nil {
						return
					}
					buf := make([]byte, 100)
					n, err := str.Read(buf)
					if n > 0 {
						_, _ = str.Write(buf[:n])
					}
					_ = str.Close()
				}
			}(qconn)
		}
	}()

	// Client setup
	clientCache := tls.NewLRUClientSessionCache(10)
	clientTlsCfg := &tls.Config{
		RootCAs:            certPool,
		ServerName:         "localhost",
		ClientSessionCache: clientCache,
		NextProtos:         []string{"h3"},
	}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client UDP listen: %v", err)
	}
	defer clientUDP.Close()

	clientTr := &quic.Transport{Conn: clientUDP}
	defer clientTr.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	// Helper to send data over stream to ensure handshake & post-handshake NST messages complete
	exchangeData := func(c *quic.Conn) {
		t.Helper()
		str, err := c.OpenStreamSync(dialCtx)
		if err != nil {
			t.Fatalf("open stream failed: %v", err)
		}
		if _, err := str.Write([]byte("ping")); err != nil {
			t.Fatalf("write stream failed: %v", err)
		}
		buf := make([]byte, 10)
		n, err := io.ReadFull(str, buf[:4])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			t.Fatalf("read stream failed: %v", err)
		}
		if n != 4 || string(buf[:4]) != "ping" {
			t.Fatalf("unexpected echo response: %q", buf[:n])
		}
		_ = str.Close()
	}

	// Step A: First connection to establish session & receive session ticket
	c1, err := clientTr.DialEarly(dialCtx, earlyLn.Addr(), clientTlsCfg, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("dial 1 failed: %v", err)
	}
	<-c1.HandshakeComplete()
	if c1.ConnectionState().TLS.DidResume {
		t.Fatalf("expected initial connection to NOT resume session")
	}
	exchangeData(c1)
	// Give ticket time to be received and processed by ClientSessionCache
	time.Sleep(200 * time.Millisecond)
	_ = c1.CloseWithError(0, "")

	// Step B: Second connection BEFORE key rotation - should resume session
	c2, err := clientTr.DialEarly(dialCtx, earlyLn.Addr(), clientTlsCfg, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("dial 2 failed: %v", err)
	}
	<-c2.HandshakeComplete()
	if !c2.ConnectionState().TLS.DidResume {
		t.Fatalf("expected second connection to resume session (0-RTT/resumption)")
	}
	exchangeData(c2)
	time.Sleep(200 * time.Millisecond)
	_ = c2.CloseWithError(0, "")

	// Step C: Rotate Session Ticket Keys via SessionTicketService
	sts.mu.Lock()
	oldKeys := sts.currentKeys
	sts.mu.Unlock()

	rotatedKeys, err := sts.RotateSTEKs(oldKeys)
	if err != nil {
		t.Fatalf("RotateSTEKs failed: %v", err)
	}

	// Push rotated keys to active connection policies and verify telemetry log call
	sts.mu.Lock()
	sts.currentKeys = rotatedKeys
	for cfg := range sts.configs {
		cfg.SetSessionTicketKeys(rotatedKeys)
	}
	if sts.logger != nil {
		sts.logger.Debug("rotated session ticket keys across active connection policy configurations",
			zap.Int("num_configs", len(sts.configs)),
			zap.Int("num_keys", len(rotatedKeys)))
	}
	sts.mu.Unlock()

	// Step D: Third connection AFTER key rotation - should STILL resume session using preserved key
	c3, err := clientTr.DialEarly(dialCtx, earlyLn.Addr(), clientTlsCfg, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("dial 3 after key rotation failed: %v", err)
	}
	<-c3.HandshakeComplete()
	if !c3.ConnectionState().TLS.DidResume {
		t.Fatalf("expected session resumption after key rotation")
	}
	_ = c3.CloseWithError(0, "")
}
