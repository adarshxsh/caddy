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

func generateTestCert(t *testing.T, org string, serial int64) (certmagic.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsedLeaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
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

func TestCustomCertSelectionPolicy_LazyParsingAndNilLeaf(t *testing.T) {
	cert1, der1 := generateTestCert(t, "OrgA", 1001)
	cert2, der2 := generateTestCert(t, "OrgB", 1002)

	// Create unparsed certificate copies with Leaf set to nil
	cert1NilLeaf := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			PrivateKey:  cert1.PrivateKey,
			Leaf:        nil,
		},
		Tags: []string{"tag-a"},
	}

	cert2NilLeaf := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der2},
			PrivateKey:  cert2.PrivateKey,
			Leaf:        nil,
		},
		Tags: []string{"tag-b"},
	}

	// Create a certificate with nil Leaf and empty DER bytes
	certEmptyDER := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{},
			Leaf:        nil,
		},
		Tags: []string{"tag-empty"},
	}

	// Create a certificate with nil Leaf and invalid DER bytes
	certInvalidDER := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid der bytes")},
			Leaf:        nil,
		},
		Tags: []string{"tag-invalid"},
	}

	helloInfo := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	t.Run("Lazy parse leaf for SerialNumber policy", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1001)}},
		}

		choices := []certmagic.Certificate{cert2NilLeaf, cert1NilLeaf}
		selected, err := policy.SelectCertificate(helloInfo, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatalf("expected selected certificate leaf to be populated lazily")
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(1001)) != 0 {
			t.Errorf("expected serial number 1001, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("Lazy parse leaf for SubjectOrganization policy", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgB"},
		}

		choices := []certmagic.Certificate{cert1NilLeaf, cert2NilLeaf}
		selected, err := policy.SelectCertificate(helloInfo, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatalf("expected selected certificate leaf to be populated lazily")
		}
		if len(selected.Leaf.Subject.Organization) == 0 || selected.Leaf.Subject.Organization[0] != "OrgB" {
			t.Errorf("expected organization OrgB, got %v", selected.Leaf.Subject.Organization)
		}
	})

	t.Run("Lazy parse leaf for PublicKeyAlgorithm policy", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}

		choices := []certmagic.Certificate{cert1NilLeaf}
		selected, err := policy.SelectCertificate(helloInfo, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatalf("expected selected certificate leaf to be populated lazily")
		}
		if selected.Leaf.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("expected ECDSA algorithm, got %v", selected.Leaf.PublicKeyAlgorithm)
		}
	})

	t.Run("Nil leaf with invalid or empty DER skipped on leaf criteria", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgA"},
		}

		// certEmptyDER and certInvalidDER have nil Leaf and cannot be parsed.
		// They must be skipped safely without panic.
		choices := []certmagic.Certificate{certEmptyDER, certInvalidDER, cert1NilLeaf}
		selected, err := policy.SelectCertificate(helloInfo, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed for cert1NilLeaf, got: %v", err)
		}
		if selected.Leaf == nil || selected.Leaf.SerialNumber.Cmp(big.NewInt(1001)) != 0 {
			t.Errorf("expected selected cert to be cert1NilLeaf")
		}
	})

	t.Run("Nil leaf with invalid DER matches tag criteria without panic", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"tag-invalid"},
		}

		choices := []certmagic.Certificate{certInvalidDER, cert1NilLeaf}
		selected, err := policy.SelectCertificate(helloInfo, choices)
		if err != nil {
			t.Fatalf("expected tag selection to succeed, got: %v", err)
		}
		if !selected.HasTag("tag-invalid") {
			t.Errorf("expected selected certificate to have tag 'tag-invalid'")
		}
	})

	t.Run("No matching certificates returns error without panic", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(9999)}},
		}

		choices := []certmagic.Certificate{certEmptyDER, certInvalidDER, cert1NilLeaf}
		_, err := policy.SelectCertificate(helloInfo, choices)
		if err == nil {
			t.Fatalf("expected error when no certs match policy, got nil")
		}
	})
}
