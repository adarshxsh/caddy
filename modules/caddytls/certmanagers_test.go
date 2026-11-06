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

func TestHTTPCertGetter_Provision(t *testing.T) {
	hcg := &HTTPCertGetter{}
	if err := hcg.Provision(caddy.Context{}); err == nil {
		t.Errorf("expected error when URL is empty, got nil")
	}

	hcg.URL = "http://example.com/cert"
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Errorf("expected no error when URL is set, got %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_HandshakeContextCancellation(t *testing.T) {
	reqReceived := make(chan struct{})
	server := httptest.Server{
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(reqReceived)
				// Wait until the request context is canceled
				<-r.Context().Done()
			}),
		},
	}
	// Manual listener setup for httptest
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server.Listener = l
	server.Start()
	defer server.Close()

	hcg := HTTPCertGetter{
		URL: server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		hello := &tls.ClientHelloInfo{
			ServerName: "example.com",
			Conn:       &fakeConn{localAddr: l.Addr()},
		}
		_, err := hcg.GetCertificate(ctx, hello)
		errChan <- err
	}()

	// Wait for the request to reach the server handler
	select {
	case <-reqReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP request to reach server")
	}

	// Cancel the handshake context
	cancel()

	select {
	case err := <-errChan:
		if err == nil {
			t.Errorf("expected error due to canceled context, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for GetCertificate to return after context cancellation")
	}
}

func TestHTTPCertGetter_GetCertificate(t *testing.T) {
	pemBundle, err := generateTestCertAndKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("server_name") == "nocontent.com" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Query().Get("server_name") == "error.com" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBundle)
	}))
	defer server.Close()

	hcg := HTTPCertGetter{URL: server.URL}
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       &fakeConn{localAddr: server.Listener.Addr()},
	}

	// Test successful cert retrieval
	cert, err := hcg.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected certificate, got nil")
	}

	// Test 204 No Content
	helloNoContent := &tls.ClientHelloInfo{
		ServerName: "nocontent.com",
		Conn:       &fakeConn{localAddr: server.Listener.Addr()},
	}
	cert204, err := hcg.GetCertificate(context.Background(), helloNoContent)
	if err != nil {
		t.Fatalf("unexpected error for 204 response: %v", err)
	}
	if cert204 != nil {
		t.Fatalf("expected nil cert for 204 response, got %v", cert204)
	}

	// Test 500 Internal Server Error
	helloErr := &tls.ClientHelloInfo{
		ServerName: "error.com",
		Conn:       &fakeConn{localAddr: server.Listener.Addr()},
	}
	_, err = hcg.GetCertificate(context.Background(), helloErr)
	if err == nil {
		t.Fatalf("expected error for 500 response, got nil")
	}
}

type fakeConn struct {
	net.Conn
	localAddr net.Addr
}

func (f *fakeConn) LocalAddr() net.Addr {
	if f.localAddr != nil {
		return f.localAddr
	}
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func generateTestCertAndKeyPEM() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDer})

	return append(certPEM, keyPEM...), nil
}
