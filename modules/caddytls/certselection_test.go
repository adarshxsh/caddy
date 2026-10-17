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

func generateTestCertificate(t *testing.T, serial *big.Int, org string) ([]byte, *x509.Certificate) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   "example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
		PublicKeyAlgorithm:    x509.ECDSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return der, parsed
}

func TestGetOrParseLeaf(t *testing.T) {
	der, parsed := generateTestCertificate(t, big.NewInt(12345), "TestOrg")

	t.Run("nil cert struct pointer", func(t *testing.T) {
		if leaf := getOrParseLeaf(nil); leaf != nil {
			t.Errorf("expected nil leaf for nil cert pointer, got %v", leaf)
		}
	})

	t.Run("pre-populated Leaf", func(t *testing.T) {
		cert := &certmagic.Certificate{
			Certificate: tls.Certificate{
				Leaf: parsed,
			},
		}
		leaf := getOrParseLeaf(cert)
		if leaf != parsed {
			t.Errorf("expected returned leaf to match pre-populated Leaf")
		}
	})

	t.Run("nil Leaf with valid DER in Certificate[0]", func(t *testing.T) {
		cert := &certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{der},
			},
		}
		if cert.Leaf != nil {
			t.Fatalf("expected Leaf to be nil initially")
		}
		leaf := getOrParseLeaf(cert)
		if leaf == nil {
			t.Fatalf("expected getOrParseLeaf to return parsed leaf, got nil")
		}
		if leaf.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
			t.Errorf("expected serial number 12345, got %v", leaf.SerialNumber)
		}
		if cert.Leaf != leaf {
			t.Errorf("expected cert.Leaf to be set after getOrParseLeaf")
		}
	})

	t.Run("nil Leaf with empty Certificate slice", func(t *testing.T) {
		cert := &certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{},
			},
		}
		if leaf := getOrParseLeaf(cert); leaf != nil {
			t.Errorf("expected nil leaf for empty Certificate slice, got %v", leaf)
		}
	})

	t.Run("nil Leaf with invalid DER bytes", func(t *testing.T) {
		cert := &certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{[]byte("invalid der")},
			},
		}
		if leaf := getOrParseLeaf(cert); leaf != nil {
			t.Errorf("expected nil leaf for invalid DER bytes, got %v", leaf)
		}
	})
}

func TestSelectCertificateNilLeafHandling(t *testing.T) {
	der1, _ := generateTestCertificate(t, big.NewInt(1001), "OrgA")
	der2, _ := generateTestCertificate(t, big.NewInt(1002), "OrgB")

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	t.Run("matching SerialNumber with nil Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1002)}},
		}

		choices := []certmagic.Certificate{
			{Certificate: tls.Certificate{Certificate: [][]byte{[]byte("corrupt_bytes")}}}, // nil Leaf, corrupt DER
			{Certificate: tls.Certificate{Certificate: [][]byte{der1}}},                    // nil Leaf, serial 1001
			{Certificate: tls.Certificate{Certificate: [][]byte{der2}}},                    // nil Leaf, serial 1002
		}

		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error selecting cert: %v", err)
		}
		if selected.Leaf == nil || selected.Leaf.SerialNumber.Cmp(big.NewInt(1002)) != 0 {
			t.Errorf("expected selected certificate with serial number 1002")
		}
	})

	t.Run("matching SubjectOrganization with nil Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgA"},
		}

		choices := []certmagic.Certificate{
			{Certificate: tls.Certificate{Certificate: [][]byte{[]byte("invalid")}}}, // nil Leaf, invalid
			{Certificate: tls.Certificate{Certificate: [][]byte{der2}}},              // nil Leaf, OrgB
			{Certificate: tls.Certificate{Certificate: [][]byte{der1}}},              // nil Leaf, OrgA
		}

		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error selecting cert: %v", err)
		}
		if selected.Leaf == nil || !slicesContains(selected.Leaf.Subject.Organization, "OrgA") {
			t.Errorf("expected selected cert with OrgA")
		}
	})

	t.Run("matching PublicKeyAlgorithm with nil Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}

		choices := []certmagic.Certificate{
			{Certificate: tls.Certificate{Certificate: [][]byte{[]byte("invalid")}}}, // nil Leaf, invalid
			{Certificate: tls.Certificate{Certificate: [][]byte{der1}}},              // nil Leaf, ECDSA
		}

		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error selecting cert: %v", err)
		}
		if selected.Leaf == nil || selected.Leaf.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("expected selected cert with ECDSA public key algorithm")
		}
	})

	t.Run("no choices match returns error without panic", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"NonExistentOrg"},
		}

		choices := []certmagic.Certificate{
			{Certificate: tls.Certificate{Certificate: [][]byte{[]byte("invalid")}}},
			{Certificate: tls.Certificate{Certificate: [][]byte{der1}}},
		}

		_, err := policy.SelectCertificate(hello, choices)
		if err == nil {
			t.Fatalf("expected error when no certs match, got nil")
		}
	})

	t.Run("tag matching with nil Leaf and invalid DER", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"tag1"},
		}

		choices := []certmagic.Certificate{
			{
				Tags:        []string{"tag1"},
				Certificate: tls.Certificate{Certificate: [][]byte{[]byte("invalid")}},
			},
		}

		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error selecting tag-matched cert: %v", err)
		}
		if !selected.HasTag("tag1") {
			t.Errorf("expected selected certificate with tag1")
		}
	})
}

func slicesContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
