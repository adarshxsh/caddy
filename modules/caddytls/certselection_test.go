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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func generateTestCert(t *testing.T, serial int64, org string) (certmagic.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNum := big.NewInt(serial)
	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsedLeaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	cert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  priv,
			Leaf:        parsedLeaf,
		},
	}

	return cert, derBytes
}

func TestSelectCertificate_NilLeaf(t *testing.T) {
	cert, derBytes := generateTestCert(t, 12345, "TestOrg")

	// Create candidate choice with Leaf == nil but raw DER bytes present
	unparsedCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  cert.PrivateKey,
			Leaf:        nil,
		},
	}

	// Create candidate choice with Leaf == nil and empty raw DER bytes
	emptyCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: nil,
			Leaf:        nil,
		},
		Tags: []string{"tag1"},
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	t.Run("Lazy parse Leaf on demand for SerialNumber match", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{unparsedCert})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf == nil {
			t.Errorf("expected selected cert to have Leaf populated")
		} else if selected.Leaf.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
			t.Errorf("expected serial number 12345, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("Lazy parse Leaf on demand for SubjectOrganization match", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"TestOrg"},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{unparsedCert})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf == nil {
			t.Errorf("expected selected cert to have Leaf populated")
		}
	})

	t.Run("Lazy parse Leaf on demand for PublicKeyAlgorithm match", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{unparsedCert})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf == nil {
			t.Errorf("expected selected cert to have Leaf populated")
		}
	})

	t.Run("Nil leaf without DER bytes skipped for leaf-dependent rules", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
		}
		_, err := policy.SelectCertificate(hello, []certmagic.Certificate{emptyCert})
		if err == nil {
			t.Fatalf("expected error when no certs match, got nil")
		}
	})

	t.Run("Nil leaf without DER bytes matched by tag rule", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"tag1"},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{emptyCert})
		if err != nil {
			t.Fatalf("expected selection by tag to succeed, got error: %v", err)
		}
		if !selected.HasTag("tag1") {
			t.Errorf("expected selected cert to have tag1")
		}
	})
}
