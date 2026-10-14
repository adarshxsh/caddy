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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/caddyserver/certmagic"
)

func createTestCert(t *testing.T, serial *big.Int, org string, isRSA bool) ([]byte, *x509.Certificate) {
	t.Helper()
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	var err error
	if isRSA {
		rsaKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
		if errKey != nil {
			t.Fatalf("failed to generate private key: %v", errKey)
		}
		priv = rsaKey
		pub = &rsaKey.PublicKey
	} else {
		ecdsaKey, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if errKey != nil {
			t.Fatalf("failed to generate private key: %v", errKey)
		}
		priv = ecdsaKey
		pub = &ecdsaKey.PublicKey
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	return der, parsed
}

func TestCustomCertSelectionPolicy_UnparsedLeaf(t *testing.T) {
	serial1 := big.NewInt(1001)
	serial2 := big.NewInt(1002)

	der1, _ := createTestCert(t, serial1, "OrgA", true)  // RSA
	der2, _ := createTestCert(t, serial2, "OrgB", false) // ECDSA

	cert1Unparsed := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        nil,
		},
		Tags: []string{"tagA"},
	}
	cert2Unparsed := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der2},
			Leaf:        nil,
		},
		Tags: []string{"tagB"},
	}

	choices := []certmagic.Certificate{cert1Unparsed, cert2Unparsed}

	// 1. Filter by SerialNumber
	policySN := CustomCertSelectionPolicy{
		SerialNumber: []bigInt{{Int: *serial2}},
	}
	selected, err := policySN.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected selection by serial number to succeed, got: %v", err)
	}
	if selected.Leaf == nil {
		t.Fatalf("expected selected certificate leaf to be parsed, got nil")
	}
	if selected.Leaf.SerialNumber.Cmp(serial2) != 0 {
		t.Errorf("expected serial %v, got %v", serial2, selected.Leaf.SerialNumber)
	}

	// 2. Filter by SubjectOrganization
	policyOrg := CustomCertSelectionPolicy{
		SubjectOrganization: []string{"OrgA"},
	}
	selected, err = policyOrg.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected selection by organization to succeed, got: %v", err)
	}
	if selected.Leaf == nil {
		t.Fatalf("expected selected certificate leaf to be parsed, got nil")
	}
	if len(selected.Leaf.Subject.Organization) == 0 || selected.Leaf.Subject.Organization[0] != "OrgA" {
		t.Errorf("expected organization OrgA, got %v", selected.Leaf.Subject.Organization)
	}

	// 3. Filter by PublicKeyAlgorithm
	policyAlgo := CustomCertSelectionPolicy{
		PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
	}
	selected, err = policyAlgo.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected selection by public key algorithm to succeed, got: %v", err)
	}
	if selected.Leaf == nil {
		t.Fatalf("expected selected certificate leaf to be parsed, got nil")
	}
	if selected.Leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA public key algorithm, got %v", selected.Leaf.PublicKeyAlgorithm)
	}
}

func TestCustomCertSelectionPolicy_InvalidLeafDER(t *testing.T) {
	invalidCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid certificate der bytes")},
			Leaf:        nil,
		},
		Tags: []string{"invalid"},
	}

	choices := []certmagic.Certificate{invalidCert}

	// Filter by SerialNumber - should skip candidate without panicking
	policySN := CustomCertSelectionPolicy{
		SerialNumber: []bigInt{{Int: *big.NewInt(1234)}},
	}
	_, err := policySN.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err == nil {
		t.Fatalf("expected error when no candidate matches, got nil")
	}

	// Filter by SubjectOrganization - should skip candidate without panicking
	policyOrg := CustomCertSelectionPolicy{
		SubjectOrganization: []string{"NonExistentOrg"},
	}
	_, err = policyOrg.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err == nil {
		t.Fatalf("expected error when no candidate matches, got nil")
	}

	// Filter by PublicKeyAlgorithm - should skip candidate without panicking
	policyAlgo := CustomCertSelectionPolicy{
		PublicKeyAlgorithm: PublicKeyAlgorithm(x509.RSA),
	}
	_, err = policyAlgo.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err == nil {
		t.Fatalf("expected error when no candidate matches, got nil")
	}
}

func TestCustomCertSelectionPolicy_TagOnlyWithInvalidLeaf(t *testing.T) {
	invalidCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid certificate der bytes")},
			Leaf:        nil,
		},
		Tags: []string{"env:prod", "role:web"},
	}

	choices := []certmagic.Certificate{invalidCert}

	// Tag-only filter - should not require leaf data and should succeed based on tags
	policyTags := CustomCertSelectionPolicy{
		AllTags: []string{"env:prod"},
	}
	selected, err := policyTags.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected tag-only selection to succeed despite invalid leaf DER, got: %v", err)
	}
	if len(selected.Tags) == 0 || selected.Tags[0] != "env:prod" {
		t.Errorf("unexpected selected certificate tags: %v", selected.Tags)
	}

	// AnyTag filter
	policyAnyTag := CustomCertSelectionPolicy{
		AnyTag: []string{"role:web", "role:db"},
	}
	selected, err = policyAnyTag.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected AnyTag selection to succeed, got: %v", err)
	}
	if len(selected.Tags) < 2 || selected.Tags[1] != "role:web" {
		t.Errorf("unexpected selected certificate tags: %v", selected.Tags)
	}
}

func TestCustomCertSelectionPolicy_PreParsedLeaf(t *testing.T) {
	serial := big.NewInt(2024)
	der, parsed := createTestCert(t, serial, "ExampleCorp", true)

	cert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der},
			Leaf:        parsed,
		},
		Tags: []string{"tag1"},
	}

	choices := []certmagic.Certificate{cert}

	policy := CustomCertSelectionPolicy{
		SerialNumber:        []bigInt{{Int: *serial}},
		SubjectOrganization: []string{"ExampleCorp"},
		PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.RSA),
		AllTags:             []string{"tag1"},
	}

	selected, err := policy.SelectCertificate(&tls.ClientHelloInfo{}, choices)
	if err != nil {
		t.Fatalf("expected pre-parsed leaf selection to succeed, got: %v", err)
	}
	if selected.Leaf == nil || selected.Leaf.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("expected selected cert serial %v, got %v", serial, selected.Leaf)
	}
}
