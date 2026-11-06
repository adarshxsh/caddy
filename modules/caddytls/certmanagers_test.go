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
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func generateTestPEMBundle(t *testing.T) []byte {
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
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return append(certPem, keyPem...)
}

func TestHTTPCertGetter_HandshakeContextCancellation(t *testing.T) {
	// Server that blocks until request context is canceled or handler finishes after delay
	serverStarted := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(serverStarted)
		select {
		case <-r.Context().Done():
			// Context canceled as expected
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	hcg := &HTTPCertGetter{URL: ts.URL}
	provCtx, cancelProv := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancelProv()
	if err := hcg.Provision(provCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	handshakeCtx, cancelHandshake := context.WithCancel(context.Background())

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	errChan := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(handshakeCtx, hello)
		errChan <- err
	}()

	// Wait until server receives request then cancel handshake context
	<-serverStarted
	cancelHandshake()

	select {
	case err := <-errChan:
		if err == nil {
			t.Fatal("expected error due to canceled handshake context, got nil")
		}
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("expected context canceled error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetCertificate did not return promptly after handshake context cancellation")
	}
}

func TestHTTPCertGetter_ReloadDoesNotInvalidateGetCertificate(t *testing.T) {
	pemBundle := generateTestPEMBundle(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBundle)
	}))
	defer ts.Close()

	hcg := &HTTPCertGetter{URL: ts.URL}

	// Create provisioning context and cancel it immediately to simulate a config reload/unload
	provCtx, cancelProv := context.WithCancel(context.Background())
	caddyCtx, cancelCaddy := caddy.NewContext(caddy.Context{Context: provCtx})
	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	cancelCaddy()
	cancelProv()

	// Call GetCertificate with an active handshake context
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("GetCertificate failed despite active handshake context: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate, got nil")
	}
}

type mockConn struct {
	net.Conn
	localAddr net.Addr
}

func (m mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

type mockAddr string

func (a mockAddr) Network() string { return "tcp" }
func (a mockAddr) String() string  { return string(a) }

func TestHTTPCertGetter_QueryParamsAndResponses(t *testing.T) {
	pemBundle := generateTestPEMBundle(t)

	var lastQuery url.Values
	var responseCode int = http.StatusOK
	var responseBody []byte = pemBundle

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.Query()
		w.WriteHeader(responseCode)
		if len(responseBody) > 0 {
			_, _ = w.Write(responseBody)
		}
	}))
	defer ts.Close()

	hcg := &HTTPCertGetter{URL: ts.URL}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := hcg.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName:       "test.example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             mockConn{localAddr: mockAddr("127.0.0.1:12345")},
	}

	// Case 1: Successful cert fetch (200 OK)
	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("unexpected error on 200 OK: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}

	if got := lastQuery.Get("server_name"); got != "test.example.com" {
		t.Errorf("server_name = %q; want %q", got, "test.example.com")
	}
	if got := lastQuery.Get("signature_schemes"); got != "403" {
		t.Errorf("signature_schemes = %q; want %q", got, "403")
	}
	if got := lastQuery.Get("cipher_suites"); got != "1301" {
		t.Errorf("cipher_suites = %q; want %q", got, "1301")
	}
	if got := lastQuery.Get("local_ip"); got != "127.0.0.1" {
		t.Errorf("local_ip = %q; want %q", got, "127.0.0.1")
	}

	// Case 2: 204 No Content
	responseCode = http.StatusNoContent
	responseBody = nil
	cert, err = hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("unexpected error on 204 No Content: %v", err)
	}
	if cert != nil {
		t.Errorf("expected nil cert on 204, got %v", cert)
	}

	// Case 3: 500 Internal Server Error
	responseCode = http.StatusInternalServerError
	cert, err = hcg.GetCertificate(context.Background(), hello)
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "got HTTP 500") {
		t.Errorf("expected error message to contain 'got HTTP 500', got %v", err)
	}
}
