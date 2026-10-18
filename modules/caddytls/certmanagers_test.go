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

func TestHTTPCertGetterProvision(t *testing.T) {
	var hcg HTTPCertGetter

	// Empty URL should return error
	if err := hcg.Provision(caddy.Context{}); err == nil {
		t.Error("expected error for empty URL, got nil")
	}

	// Valid URL should succeed
	hcg.URL = "http://example.com/cert"
	if err := hcg.Provision(caddy.Context{}); err != nil {
		t.Errorf("unexpected error for valid URL: %v", err)
	}
}

func generateSelfSignedCertAndKeyPEM() ([]byte, error) {
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

type dummyConn struct {
	net.Conn
	localAddr net.Addr
}

func (c dummyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func TestHTTPCertGetterGetCertificate(t *testing.T) {
	certPEM, err := generateSelfSignedCertAndKeyPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	handlerQueryChan := make(chan string, 1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/success":
			select {
			case handlerQueryChan <- r.URL.RawQuery:
			default:
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		case "/nocontent":
			w.WriteHeader(http.StatusNoContent)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		case "/slow":
			// Wait until request context is cancelled
			<-r.Context().Done()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	hcg := HTTPCertGetter{URL: ts.URL + "/success"}

	conn := dummyConn{localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	hello := &tls.ClientHelloInfo{
		ServerName:       "example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		Conn:             conn,
	}

	t.Run("success", func(t *testing.T) {
		cert, err := hcg.GetCertificate(context.Background(), hello)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert == nil {
			t.Fatal("expected cert, got nil")
		}

		select {
		case rawQuery := <-handlerQueryChan:
			if rawQuery == "" {
				t.Error("expected query parameters, got empty")
			}
		case <-time.After(time.Second):
			t.Error("timed out waiting for query string")
		}
	})

	t.Run("nocontent", func(t *testing.T) {
		hcgNoContent := HTTPCertGetter{URL: ts.URL + "/nocontent"}
		cert, err := hcgNoContent.GetCertificate(context.Background(), hello)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != nil {
			t.Errorf("expected nil cert for 204 No Content, got %v", cert)
		}
	})

	t.Run("error status", func(t *testing.T) {
		hcgErr := HTTPCertGetter{URL: ts.URL + "/error"}
		_, err := hcgErr.GetCertificate(context.Background(), hello)
		if err == nil {
			t.Fatal("expected error for HTTP 500, got nil")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		hcgSlow := HTTPCertGetter{URL: ts.URL + "/slow"}
		ctx, cancel := context.WithCancel(context.Background())

		errChan := make(chan error, 1)
		go func() {
			_, err := hcgSlow.GetCertificate(ctx, hello)
			errChan <- err
		}()

		// Cancel context shortly after request starts
		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case err := <-errChan:
			if err == nil {
				t.Fatal("expected error on cancelled context, got nil")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("GetCertificate did not return promptly after context cancellation")
		}
	})
}
