package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

type dummyConn struct {
	net.Conn
	localAddr net.Addr
}

func (c dummyConn) LocalAddr() net.Addr { return c.localAddr }

func TestHTTPCertGetter_Provision(t *testing.T) {
	hcg := HTTPCertGetter{}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := hcg.Provision(caddyCtx); err == nil {
		t.Errorf("expected error when URL is empty, got nil")
	}

	hcg.URL = "http://example.com/cert"
	if err := hcg.Provision(caddyCtx); err != nil {
		t.Errorf("unexpected error on Provision: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_ContextCancellation(t *testing.T) {
	reqReceived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqReceived)
		// Wait until request context is canceled by client disconnect
		<-r.Context().Done()
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	caddyCtx, cancelProvision := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancelProvision()

	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	handshakeCtx, cancelHandshake := context.WithCancel(context.Background())

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{localAddr: dummyAddr("127.0.0.1:1234")},
	}

	errChan := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(handshakeCtx, hello)
		errChan <- err
	}()

	// Wait for request to reach server
	select {
	case <-reqReceived:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not receive request in time")
	}

	// Cancel handshake context
	cancelHandshake()

	select {
	case err := <-errChan:
		if err == nil {
			t.Errorf("expected error due to context cancellation, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("GetCertificate did not return promptly after context cancellation")
	}
}

func TestHTTPCertGetter_GetCertificate_AfterModuleReload(t *testing.T) {
	certPEM := generateTestCertPEM(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query parameters
		if r.URL.Query().Get("server_name") != "example.com" {
			t.Errorf("expected server_name query param 'example.com', got '%s'", r.URL.Query().Get("server_name"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}

	// Simulate original provisioning context
	provCtx, cancelProv := context.WithCancel(context.Background())
	caddyCtx, cancelCaddy := caddy.NewContext(caddy.Context{Context: provCtx})
	defer cancelCaddy()

	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Cancel the original provisioning context (simulating Caddy config reload / module stop)
	cancelProv()

	// Perform TLS handshake lookup using fresh handshake context
	freshHandshakeCtx := context.Background()
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{localAddr: dummyAddr("127.0.0.1:1234")},
	}

	cert, err := hcg.GetCertificate(freshHandshakeCtx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed after provisioning context cancellation: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected non-nil certificate, got nil")
	}
}

func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Caddy Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return append(certPEM, keyPEM...)
}
