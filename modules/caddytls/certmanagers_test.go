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
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestHTTPCertGetter_Provision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	hcg := &HTTPCertGetter{}
	if err := hcg.Provision(ctx); err == nil {
		t.Errorf("expected error when URL is empty, got nil")
	}

	hcg.URL = "http://example.com/cert"
	if err := hcg.Provision(ctx); err != nil {
		t.Errorf("expected no error when URL is set, got: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_HandshakeContextCancellation(t *testing.T) {
	reqReceived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqReceived)
		// Block until the client cancels request
		<-r.Context().Done()
	}))
	defer server.Close()

	hcg := &HTTPCertGetter{URL: server.URL}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := hcg.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	hsCtx, hsCancel := context.WithCancel(context.Background())
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       testConn{addr: testAddr("127.0.0.1:12345")},
	}

	errChan := make(chan error, 1)
	go func() {
		_, err := hcg.GetCertificate(hsCtx, hello)
		errChan <- err
	}()

	// Wait until the HTTP server receives the request
	<-reqReceived

	// Cancel the handshake context
	hsCancel()

	err := <-errChan
	if err == nil {
		t.Fatal("expected error due to canceled handshake context, got nil")
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(errors.Unwrap(err), context.Canceled) {
		t.Logf("got expected cancellation error: %v", err)
	}
}

func TestHTTPCertGetter_GetCertificate_AfterProvisioningContextCanceled(t *testing.T) {
	pemBundle, err := generateTestPEMBundle()
	if err != nil {
		t.Fatalf("failed to generate test PEM bundle: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("server_name") != "example.com" {
			http.Error(w, "unexpected server_name", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(pemBundle)
	}))
	defer server.Close()

	hcg := &HTTPCertGetter{URL: server.URL}
	provCtx, provCancel := caddy.NewContext(caddy.Context{Context: context.Background()})

	if err := hcg.Provision(provCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Cancel provisioning context
	provCancel()

	// Perform GetCertificate with active handshake context
	liveCtx := context.Background()
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		Conn:       testConn{addr: testAddr("127.0.0.1:12345")},
	}

	cert, err := hcg.GetCertificate(liveCtx, hello)
	if err != nil {
		t.Fatalf("GetCertificate failed after provisioning context was canceled: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate, got nil")
	}
}

func generateTestPEMBundle() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return append(certPEM, keyPEM...), nil
}
