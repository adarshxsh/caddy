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
)

type dummyConn struct {
	net.Conn
	localAddr net.Addr
}

func (c dummyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func generateTestPEMBundle(t *testing.T) []byte {
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
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to encode cert PEM: %v", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("failed to encode key PEM: %v", err)
	}

	return buf.Bytes()
}

func TestHTTPCertGetter_GetCertificate_Success(t *testing.T) {
	pemBundle := generateTestPEMBundle(t)

	var receivedSNI, receivedSigs, receivedSuites, receivedLocalIP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSNI = r.URL.Query().Get("server_name")
		receivedSigs = r.URL.Query().Get("signature_schemes")
		receivedSuites = r.URL.Query().Get("cipher_suites")
		receivedLocalIP = r.URL.Query().Get("local_ip")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBundle)
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             dummyConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
	}

	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	if receivedSNI != "example.com" {
		t.Errorf("expected server_name example.com, got %q", receivedSNI)
	}
	if receivedSigs != "403" { // 0x0403 in hex is 403
		t.Errorf("expected signature_schemes 403, got %q", receivedSigs)
	}
	if receivedSuites != "1301" { // 0x1301 in hex is 1301
		t.Errorf("expected cipher_suites 1301, got %q", receivedSuites)
	}
	if receivedLocalIP != "127.0.0.1" {
		t.Errorf("expected local_ip 127.0.0.1, got %q", receivedLocalIP)
	}
}

func TestHTTPCertGetter_GetCertificate_ContextCanceled(t *testing.T) {
	reqReceived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqReceived)
		<-r.Context().Done()
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(ctx, hello)
		errCh <- err
	}()

	<-reqReceived
	cancel()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error due to canceled context, got nil")
	}
}

func TestHTTPCertGetter_GetCertificate_StatusNoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
	}

	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert != nil {
		t.Fatalf("expected nil certificate for HTTP 204, got %v", cert)
	}
}

func TestHTTPCertGetter_GetCertificate_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       dummyConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
	}

	_, err := hcg.GetCertificate(context.Background(), hello)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}
