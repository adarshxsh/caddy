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

func generateTestCert(t *testing.T, serial *big.Int, org string) (certmagic.Certificate, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		PublicKeyAlgorithm: x509.ECDSA,
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  privateKey,
		},
	}
	return cert, derBytes
}

func TestSelectCertificate_LazyLeafParsing(t *testing.T) {
	serial := big.NewInt(998877)
	org := "Caddy Test Org"
	cert, _ := generateTestCert(t, serial, "Caddy Test Org")

	// Ensure Leaf is nil initially to test lazy parsing
	cert.Leaf = nil

	policy := CustomCertSelectionPolicy{
		SerialNumber:        []bigInt{{Int: *serial}},
		SubjectOrganization: []string{org},
		PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.ECDSA),
	}

	hello := &tls.ClientHelloInfo{}
	selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{cert})
	if err != nil {
		t.Fatalf("expected successful selection, got error: %v", err)
	}

	if selected.Leaf == nil {
		t.Fatalf("expected selected.Leaf to be populated lazily, but got nil")
	}

	if selected.Leaf.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("expected serial %v, got %v", serial, selected.Leaf.SerialNumber)
	}
}

func TestSelectCertificate_UnparseableLeaf(t *testing.T) {
	// Candidate with nil Leaf and bad DER bytes
	badCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("not a valid DER certificate")},
		},
	}

	hello := &tls.ClientHelloInfo{}

	tests := []struct {
		name   string
		policy CustomCertSelectionPolicy
	}{
		{
			name: "SerialNumber rule",
			policy: CustomCertSelectionPolicy{
				SerialNumber: []bigInt{{Int: *big.NewInt(12345)}},
			},
		},
		{
			name: "SubjectOrganization rule",
			policy: CustomCertSelectionPolicy{
				SubjectOrganization: []string{"Any Org"},
			},
		},
		{
			name: "PublicKeyAlgorithm rule",
			policy: CustomCertSelectionPolicy{
				PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.policy.SelectCertificate(hello, []certmagic.Certificate{badCert})
			if err == nil {
				t.Fatalf("expected error when filtering unparseable leaf, but selection succeeded")
			}
		})
	}
}

func TestSelectCertificate_TagSelectionWithNilLeaf(t *testing.T) {
	// Candidate with nil Leaf and empty certificate bytes, but tagged
	taggedCert := certmagic.Certificate{
		Tags: []string{"env:prod", "region:us-east"},
	}

	policy := CustomCertSelectionPolicy{
		AnyTag:  []string{"env:prod"},
		AllTags: []string{"region:us-east"},
	}

	hello := &tls.ClientHelloInfo{}
	selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{taggedCert})
	if err != nil {
		t.Fatalf("expected tag-based selection to succeed with nil leaf, got error: %v", err)
	}

	if !selected.HasTag("env:prod") {
		t.Errorf("expected selected cert to have tag env:prod")
	}
}

func TestSelectCertificate_NoMatch(t *testing.T) {
	serial := big.NewInt(111)
	cert, _ := generateTestCert(t, serial, "Org A")
	cert.Leaf = nil

	policy := CustomCertSelectionPolicy{
		SerialNumber: []bigInt{{Int: *big.NewInt(999)}},
	}

	hello := &tls.ClientHelloInfo{}
	_, err := policy.SelectCertificate(hello, []certmagic.Certificate{cert})
	if err == nil {
		t.Fatalf("expected error when no certificates match policy, got nil")
	}
}
