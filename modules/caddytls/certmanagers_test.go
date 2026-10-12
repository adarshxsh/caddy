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

func generateTestCertPEM(t *testing.T, domain string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return append(certPEM, keyPEM...)
}

type mockConn struct {
	net.Conn
	localAddr net.Addr
}

func (m mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func TestHTTPCertGetter_Provision(t *testing.T) {
	// Missing URL
	hcgEmpty := &HTTPCertGetter{}
	if err := hcgEmpty.Provision(caddy.Context{}); err == nil {
		t.Error("expected error when URL is empty, got nil")
	}

	// Valid URL
	hcgValid := &HTTPCertGetter{URL: "https://example.com/cert"}
	if err := hcgValid.Provision(caddy.Context{}); err != nil {
		t.Errorf("unexpected error for valid URL: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_ContextPropagation(t *testing.T) {
	certPEM := generateTestCertPEM(t, "example.com")

	requestReceived := make(chan struct{})
	var recServerName, recSigSchemes, recCipherSuites, recLocalIP string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recServerName = r.URL.Query().Get("server_name")
		recSigSchemes = r.URL.Query().Get("signature_schemes")
		recCipherSuites = r.URL.Query().Get("cipher_suites")
		recLocalIP = r.URL.Query().Get("local_ip")
		close(requestReceived)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL}
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		Conn: mockConn{
			localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cert, err := hcg.GetCertificate(ctx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert, got nil")
	}

	select {
	case <-requestReceived:
	default:
		t.Fatal("request was not received by test server")
	}

	if recServerName != "example.com" {
		t.Errorf("expected server_name 'example.com', got '%s'", recServerName)
	}
	if recSigSchemes != "403" { // 0x0403 for ECDSAWithP256AndSHA256
		t.Errorf("expected signature_schemes '403', got '%s'", recSigSchemes)
	}
	if recCipherSuites != "c02b" { // 0xc02b for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		t.Errorf("expected cipher_suites 'c02b', got '%s'", recCipherSuites)
	}
	if recLocalIP != "127.0.0.1" {
		t.Errorf("expected local_ip '127.0.0.1', got '%s'", recLocalIP)
	}
}

func TestHTTPCertGetter_GetCertificate_ProvisioningContextCancellation(t *testing.T) {
	certPEM := generateTestCertPEM(t, "example.com")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer ts.Close()

	// Create and cancel a provisioning context
	provCtx, cancelProv := context.WithCancel(context.Background())
	cancelProv()

	hcg := HTTPCertGetter{URL: ts.URL}
	// Provision with cancelled context
	if err := hcg.Provision(caddy.Context{Context: provCtx}); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn: mockConn{
			localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		},
	}

	// Active handshake context
	handshakeCtx := context.Background()
	cert, err := hcg.GetCertificate(handshakeCtx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed despite cancelled provisioning context: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert, got nil")
	}
}

func TestHTTPCertGetter_GetCertificate_HandshakeContextCancellation(t *testing.T) {
	serverBlock := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-serverBlock
	}))
	defer func() {
		close(serverBlock)
		ts.Close()
	}()

	hcg := HTTPCertGetter{URL: ts.URL}
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn: mockConn{
			localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		},
	}

	handshakeCtx, cancelHandshake := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(handshakeCtx, hello)
		errChan <- err
	}()

	// Cancel the handshake context while HTTP request is in flight
	cancelHandshake()

	select {
	case err := <-errChan:
		if err == nil {
			t.Fatal("expected error on cancelled handshake context, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for GetCertificate to return after context cancellation")
	}
}

func TestHTTPCertGetter_GetCertificate_StatusCodes(t *testing.T) {
	t.Run("StatusNoContent", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer ts.Close()

		hcg := HTTPCertGetter{URL: ts.URL}
		hello := &tls.ClientHelloInfo{
			ServerName: "example.com",
			Conn: mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
			},
		}

		cert, err := hcg.GetCertificate(context.Background(), hello)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != nil {
			t.Fatalf("expected nil certificate for 204 No Content, got %v", cert)
		}
	})

	t.Run("StatusInternalServerError", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		hcg := HTTPCertGetter{URL: ts.URL}
		hello := &tls.ClientHelloInfo{
			ServerName: "example.com",
			Conn: mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
			},
		}

		_, err := hcg.GetCertificate(context.Background(), hello)
		if err == nil {
			t.Fatal("expected error for 500 status code, got nil")
		}
	})
}
