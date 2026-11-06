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

func generateTestCertAndKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return append(certPem, keyPem...)
}

func fakeClientHelloInfo() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             &fakeConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}},
	}
}

type fakeConn struct {
	net.Conn
	localAddr net.Addr
}

func (f *fakeConn) LocalAddr() net.Addr {
	return f.localAddr
}

func TestHTTPCertGetter_Provision(t *testing.T) {
	var hcg HTTPCertGetter
	if err := hcg.Provision(caddy.Context{}); err == nil {
		t.Errorf("expected error when URL is empty, got nil")
	}

	hcg.URL = "http://localhost:8080/cert"
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Errorf("expected no error when URL is set, got: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_SuccessAndNoContent(t *testing.T) {
	certPemBundle := generateTestCertAndKeyPEM(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("server_name") != "example.com" {
			http.Error(w, "missing or invalid server_name", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("signature_schemes") != "403" { // 0x0403 for ECDSAWithP256AndSHA256
			http.Error(w, "invalid signature_schemes", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("cipher_suites") != "1301" { // 0x1301 for TLS_AES_128_GCM_SHA256
			http.Error(w, "invalid cipher_suites", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("local_ip") != "127.0.0.1" {
			http.Error(w, "invalid local_ip", http.StatusBadRequest)
			return
		}

		switch r.URL.Path {
		case "/cert":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPemBundle)
		case "/nocontent":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL + "/cert"}
	cert, err := hcg.GetCertificate(context.Background(), fakeClientHelloInfo())
	if err != nil {
		t.Fatalf("unexpected error getting certificate: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected certificate, got nil")
	}

	hcgNoContent := HTTPCertGetter{URL: ts.URL + "/nocontent"}
	certNoContent, err := hcgNoContent.GetCertificate(context.Background(), fakeClientHelloInfo())
	if err != nil {
		t.Fatalf("unexpected error for 204 No Content: %v", err)
	}
	if certNoContent != nil {
		t.Fatalf("expected nil certificate for 204 No Content, got non-nil")
	}
}

func TestHTTPCertGetter_GetCertificate_ContextCancellation(t *testing.T) {
	reqCanceled := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(reqCanceled)
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go func() {
		_, err := hcg.GetCertificate(ctx, fakeClientHelloInfo())
		errChan <- err
	}()

	// Give request time to reach server handler, then cancel handshake context
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-reqCanceled:
		// Success: outgoing request context was canceled on server side
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server request context to be canceled")
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

func TestHTTPCertGetter_GetCertificate_ReloadResilience(t *testing.T) {
	certPemBundle := generateTestCertAndKeyPEM(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPemBundle)
	}))
	defer ts.Close()

	provCtx, provCancel := context.WithCancel(context.Background())

	hcg := HTTPCertGetter{URL: ts.URL}
	if err := hcg.Provision(caddy.Context{Context: provCtx}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Simulate application reload cancelling the provisioning context
	provCancel()

	// Perform GetCertificate with a fresh handshake context
	handshakeCtx := context.Background()
	cert, err := hcg.GetCertificate(handshakeCtx, fakeClientHelloInfo())
	if err != nil {
		t.Fatalf("GetCertificate failed after reload (canceled provisioning context): %v", err)
	}
	if cert == nil {
		t.Fatalf("expected certificate after reload, got nil")
	}
}
