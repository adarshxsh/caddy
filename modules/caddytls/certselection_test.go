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

func generateTestCert(t *testing.T, serialNumber int64, org string) ([]byte, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		DNSNames:           []string{"example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return certDER, parsed
}

func TestCustomCertSelectionPolicy_LazyParseAndNilGuard(t *testing.T) {
	certDER1, leaf1 := generateTestCert(t, 12345, "Caddy Test Org")
	certDER2, _ := generateTestCert(t, 67890, "Other Org")

	t.Run("lazy parse leaf successfully when cert.Leaf is nil", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber:        []bigInt{{Int: *big.NewInt(12345)}},
			SubjectOrganization: []string{"Caddy Test Org"},
			PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.ECDSA),
		}

		// Candidate with nil Leaf but valid DER bytes in cert.Certificate[0]
		choice := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{certDER1},
				Leaf:        nil,
			},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{choice})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatal("expected selected certificate to have populated Leaf")
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
			t.Errorf("expected serial number 12345, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("nil cert.Leaf with invalid bytes skips candidate gracefully without panic when leaf criteria specified", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
		}

		invalidChoice := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{[]byte("invalid certificate bytes")},
				Leaf:        nil,
			},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		_, err := policy.SelectCertificate(hello, []certmagic.Certificate{invalidChoice})
		if err == nil {
			t.Fatal("expected error when no candidate matches, got nil")
		}
		if err.Error() != "no certificates matched custom selection policy" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil cert.Leaf with empty certificate slice skips candidate gracefully without panic when leaf criteria specified", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"Caddy Test Org"},
		}

		emptyChoice := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{},
				Leaf:        nil,
			},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		_, err := policy.SelectCertificate(hello, []certmagic.Certificate{emptyChoice})
		if err == nil {
			t.Fatal("expected error when no candidate matches, got nil")
		}
	})

	t.Run("nil cert.Leaf preserves tag evaluation when no leaf criteria specified", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"tag1"},
		}

		invalidChoiceWithTag := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{[]byte("invalid bytes")},
				Leaf:        nil,
			},
			Tags: []string{"tag1"},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{invalidChoiceWithTag})
		if err != nil {
			t.Fatalf("expected selection by tag to succeed, got error: %v", err)
		}
		if !selected.HasTag("tag1") {
			t.Error("expected selected certificate to have tag1")
		}
	})

	t.Run("pre-parsed cert.Leaf works as expected", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
		}

		parsedChoice := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{certDER1},
				Leaf:        leaf1,
			},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{parsedChoice})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
			t.Errorf("expected serial number 12345, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("multiple choices with lazy parse filters mismatched candidates", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
		}

		choiceMismatch := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{certDER2},
				Leaf:        nil,
			},
		}

		choiceMatch := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{certDER1},
				Leaf:        nil,
			},
		}

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{choiceMismatch, choiceMatch})
		if err != nil {
			t.Fatalf("expected selection to succeed, got error: %v", err)
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
			t.Errorf("expected serial number 12345, got %v", selected.Leaf.SerialNumber)
		}
	})
}
