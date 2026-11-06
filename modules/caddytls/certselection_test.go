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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func generateTestCert(t *testing.T, org string, sn int64, isRSA bool) ([]byte, *x509.Certificate) {
	t.Helper()
	var priv any
	var pubAny any

	if isRSA {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		priv = privKey
		pubAny = &privKey.PublicKey
	} else {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		priv = privKey
		pubAny = &privKey.PublicKey
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(sn),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   "example.com",
		},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubAny, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return derBytes, parsed
}

func TestCustomCertSelectionPolicy_SelectCertificate(t *testing.T) {
	der1, leaf1 := generateTestCert(t, "OrgOne", 1001, false) // ECDSA
	der2, leaf2 := generateTestCert(t, "OrgTwo", 1002, true)  // RSA

	// Candidate 1: Leaf pre-parsed, OrgOne, SN 1001, ECDSA
	cert1 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        leaf1,
		},
		Tags: []string{"tag-a", "tag-common"},
	}

	// Candidate 2: Leaf == nil, but Certificate[0] holds valid DER (OrgTwo, SN 1002, RSA)
	cert2UnparsedLeaf := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der2},
			Leaf:        nil,
		},
		Tags: []string{"tag-b", "tag-common"},
	}

	// Candidate 3: Leaf == nil and Certificate is empty
	cert3NilLeafAndCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: nil,
			Leaf:        nil,
		},
		Tags: []string{"tag-c"},
	}

	// Candidate 4: Leaf == nil and malformed DER
	cert4MalformedDER := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("not a real cert")},
			Leaf:        nil,
		},
		Tags: []string{"tag-d"},
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	choices := []certmagic.Certificate{cert1, cert2UnparsedLeaf, cert3NilLeafAndCert, cert4MalformedDER}

	t.Run("Select by SerialNumber matching unparsed leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1002)}},
		}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || big.NewInt(1002).Cmp(leaf2.SerialNumber) != 0 {
			t.Fatalf("selected unexpected certificate")
		}
	})

	t.Run("Select by SubjectOrganization matching unparsed leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgTwo"},
		}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || selected.Certificate.Certificate[0][0] != der2[0] {
			t.Fatalf("selected unexpected certificate")
		}
	})

	t.Run("Select by PublicKeyAlgorithm matching unparsed leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.RSA),
		}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || selected.Certificate.Certificate[0][0] != der2[0] {
			t.Fatalf("selected unexpected certificate")
		}
	})

	t.Run("Nil leaf candidates skip criteria checks without panic", func(t *testing.T) {
		// Only choice is cert3NilLeafAndCert
		nilChoices := []certmagic.Certificate{cert3NilLeafAndCert}
		policy := CustomCertSelectionPolicy{
			SerialNumber:        []bigInt{{Int: *big.NewInt(9999)}},
			SubjectOrganization: []string{"NonExistentOrg"},
			PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.ECDSA),
		}
		// Since leaf == nil, criteria checks requiring leaf are skipped, cert3 is considered viable.
		selected, err := policy.SelectCertificate(hello, nilChoices)
		if err != nil {
			t.Fatalf("expected selection of nil leaf choice when checks skipped, got: %v", err)
		}
		if len(selected.Tags) == 0 || selected.Tags[0] != "tag-c" {
			t.Fatalf("expected candidate 3 to be selected")
		}
	})

	t.Run("Malformed DER candidate skips criteria checks without panic", func(t *testing.T) {
		malformedChoices := []certmagic.Certificate{cert4MalformedDER}
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(9999)}},
		}
		selected, err := policy.SelectCertificate(hello, malformedChoices)
		if err != nil {
			t.Fatalf("expected selection of malformed candidate when checks skipped, got: %v", err)
		}
		if len(selected.Tags) == 0 || selected.Tags[0] != "tag-d" {
			t.Fatalf("expected candidate 4 to be selected")
		}
	})

	t.Run("No matching certificates returns error", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(9999)}},
		}
		// Only choices with parseable leaf that do NOT match serial 9999
		parseableChoices := []certmagic.Certificate{cert1, cert2UnparsedLeaf}
		_, err := policy.SelectCertificate(hello, parseableChoices)
		if err == nil {
			t.Fatalf("expected error when no certificates match serial number, got nil")
		}
	})

	t.Run("Tag selection with unparsed leaf candidates", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AllTags: []string{"tag-b", "tag-common"},
		}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("expected selection to succeed, got: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || selected.Certificate.Certificate[0][0] != der2[0] {
			t.Fatalf("selected unexpected certificate for tags")
		}
	})
}
