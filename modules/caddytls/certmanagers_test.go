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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

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
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func TestHTTPCertGetterProvision(t *testing.T) {
	hcg := &HTTPCertGetter{}
	if err := hcg.Provision(caddy.Context{}); err == nil {
		t.Errorf("expected error when URL is empty, got nil")
	}

	hcg.URL = "http://localhost:8080/cert"
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHTTPCertGetterUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`http https://example.com/get-cert`)
	hcg := &HTTPCertGetter{}
	if err := hcg.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if hcg.URL != "https://example.com/get-cert" {
		t.Errorf("expected URL 'https://example.com/get-cert', got '%s'", hcg.URL)
	}

	// Test missing argument
	dMissing := caddyfile.NewTestDispenser(`http`)
	hcg2 := &HTTPCertGetter{}
	if err := hcg2.UnmarshalCaddyfile(dMissing); err == nil {
		t.Errorf("expected error for missing URL argument, got nil")
	}
}

func TestHTTPCertGetterGetCertificate(t *testing.T) {
	pemBundle, err := generateTestCertAndKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cert":
			if r.URL.Query().Get("server_name") != "example.com" {
				http.Error(w, "bad server_name", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(pemBundle)
		case "/no-cert":
			w.WriteHeader(http.StatusNoContent)
		case "/slow":
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Second):
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{
		URL: ts.URL + "/cert",
	}

	dummyConn, clientConn := net.Pipe()
	defer dummyConn.Close()
	defer clientConn.Close()

	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             dummyConn,
	}

	// 1. Successful cert fetch using per-handshake context
	ctx := context.Background()
	cert, err := hcg.GetCertificate(ctx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatalf("expected non-nil certificate")
	}

	// 2. HTTP 204 No Content
	hcgNoContent := HTTPCertGetter{
		URL: ts.URL + "/no-cert",
	}
	cert2, err := hcgNoContent.GetCertificate(ctx, hello)
	if err != nil {
		t.Fatalf("GetCertificate returned unexpected error on 204: %v", err)
	}
	if cert2 != nil {
		t.Fatalf("expected nil certificate on 204, got %v", cert2)
	}

	// 3. Client disconnect / Handshake context cancellation
	hcgSlow := HTTPCertGetter{
		URL: ts.URL + "/slow",
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err = hcgSlow.GetCertificate(cancelCtx, hello)
	if err == nil {
		t.Fatalf("expected error on cancelled handshake context, got nil")
	}

	// 4. Sequential requests with distinct contexts (simulating reloads/multiple handshakes)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	time.Sleep(1 * time.Millisecond) // ensure timeout expires
	defer cancel1()
	_, err = hcg.GetCertificate(ctx1, hello)
	if err == nil {
		t.Fatalf("expected error on timed out context, got nil")
	}

	// Subsequent request with valid context succeeds (no stale module context state)
	ctx2 := context.Background()
	cert3, err := hcg.GetCertificate(ctx2, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed with fresh context after previous cancelled request: %v", err)
	}
	if cert3 == nil {
		t.Fatalf("expected non-nil cert with fresh context")
	}
}
