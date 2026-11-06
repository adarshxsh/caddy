package caddytls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

func generateTestCertPEM() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Caddy Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return append(certPEM, keyPEM...), nil
}

func TestHTTPCertGetter_Provision(t *testing.T) {
	hcg := &HTTPCertGetter{}
	if err := hcg.Provision(caddy.Context{}); err == nil {
		t.Errorf("expected error for empty URL, got nil")
	}

	hcg.URL = "http://example.com/cert"
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Errorf("unexpected error for valid URL: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate(t *testing.T) {
	certPEM, err := generateTestCertPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert PEM: %v", err)
	}

	var recSNI string
	var recSigs string
	var recSuites string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recSNI = r.URL.Query().Get("server_name")
		recSigs = r.URL.Query().Get("signature_schemes")
		recSuites = r.URL.Query().Get("cipher_suites")

		if recSNI == "nocontent.example.com" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}

	dummyConn := &dummyAddrConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}

	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             dummyConn,
	}

	// 1. Successful certificate fetch with per-handshake context
	ctx := context.Background()
	cert, err := hcg.GetCertificate(ctx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected certificate, got nil")
	}
	if recSNI != "example.com" {
		t.Errorf("expected SNI example.com, got %s", recSNI)
	}
	if recSigs != "403" { // ECDSAWithP256AndSHA256 is 0x0403
		t.Errorf("expected signature scheme 403, got %s", recSigs)
	}
	if recSuites != "1301" { // TLS_AES_128_GCM_SHA256 is 0x1301
		t.Errorf("expected cipher suite 1301, got %s", recSuites)
	}

	// 2. HTTP 204 No Content
	helloNoContent := &tls.ClientHelloInfo{
		ServerName: "nocontent.example.com",
		Conn:       dummyConn,
	}
	cert, err = hcg.GetCertificate(ctx, helloNoContent)
	if err != nil {
		t.Fatalf("GetCertificate with 204 failed: %v", err)
	}
	if cert != nil {
		t.Fatalf("expected nil certificate for 204 status, got %v", cert)
	}

	// 3. Cancelled handshake context propagation
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = hcg.GetCertificate(canceledCtx, hello)
	if err == nil {
		t.Fatalf("expected error with canceled context, got nil")
	}
}

func TestHTTPCertGetter_Reload(t *testing.T) {
	certPEM, err := generateTestCertPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert PEM: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer ts.Close()

	hcg := &HTTPCertGetter{URL: ts.URL}

	// Create a module context and provision hcg
	modCtx, cancelModCtx := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := hcg.Provision(modCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	dummyConn := &dummyAddrConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn,
	}

	// 1. Handshake during active module context
	hsCtx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	cert1, err := hcg.GetCertificate(hsCtx1, hello)
	if err != nil || cert1 == nil {
		t.Fatalf("GetCertificate before reload failed: %v", err)
	}

	// 2. Simulate Caddy reload: old module context is cancelled
	cancelModCtx()

	// 3. Handshake after reload with a new per-handshake context
	hsCtx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	cert2, err := hcg.GetCertificate(hsCtx2, hello)
	if err != nil || cert2 == nil {
		t.Fatalf("GetCertificate after module context cancellation (reload) failed: %v", err)
	}
}

type dummyAddrConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *dummyAddrConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *dummyAddrConn) RemoteAddr() net.Addr { return c.remoteAddr }
