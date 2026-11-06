package caddytls

import (
	"bytes"
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

type dummyConn struct {
	net.Conn
}

func (d dummyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (d dummyConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
}

func generateSelfSignedPEMCertAndKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
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
		DNSNames:              []string{"example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to encode cert: %v", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("failed to encode key: %v", err)
	}

	return buf.Bytes()
}

func TestHTTPCertGetter_GetCertificate_Success(t *testing.T) {
	pemData := generateSelfSignedPEMCertAndKey(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("server_name") != "example.com" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("local_ip") != "127.0.0.1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemData)
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision HTTPCertGetter: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             dummyConn{},
	}

	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("expected successful cert retrieval, got: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected non-nil certificate")
	}
}

func TestHTTPCertGetter_GetCertificate_ContextCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	serverBlock := make(chan struct{})
	defer close(serverBlock)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-serverBlock:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}
	caddyCtx, cancelCaddy := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancelCaddy()

	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision HTTPCertGetter: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{},
	}

	handshakeCtx, cancelHandshake := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(handshakeCtx, hello)
		errCh <- err
	}()

	// Wait for the HTTP request to hit the server
	<-requestStarted

	// Cancel the handshake context (simulating client disconnect)
	cancelHandshake()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected error due to canceled context, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for GetCertificate to return after context cancellation")
	}
}

func TestHTTPCertGetter_GetCertificate_PostReload(t *testing.T) {
	pemData := generateSelfSignedPEMCertAndKey(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemData)
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}
	caddyCtx, cancelCaddy := caddy.NewContext(caddy.Context{Context: context.Background()})

	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision HTTPCertGetter: %v", err)
	}

	// Cancel the provisioning Caddy context (simulating config reload / unload)
	cancelCaddy()

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{},
	}

	// Certificate retrieval with active handshake context must succeed despite canceled Caddy context
	handshakeCtx := context.Background()
	cert, err := hcg.GetCertificate(handshakeCtx, hello)
	if err != nil {
		t.Fatalf("expected successful cert retrieval post-reload, got: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected non-nil certificate")
	}
}
