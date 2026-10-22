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

func generateTestCert(t *testing.T, org string, serial int64) ([]byte, *x509.Certificate) {
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
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return der, parsed
}

func TestCustomCertSelectionPolicy_SelectCertificate(t *testing.T) {
	der1, parsed1 := generateTestCert(t, "Org1", 100)
	der2, parsed2 := generateTestCert(t, "Org2", 200)

	certWithLeaf1 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        parsed1,
			Certificate: [][]byte{der1},
		},
	}
	certWithLeaf2 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        parsed2,
			Certificate: [][]byte{der2},
		},
	}

	certNilLeaf1 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        nil,
			Certificate: [][]byte{der1},
		},
	}
	certNilLeaf2 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        nil,
			Certificate: [][]byte{der2},
		},
	}

	certMalformedLeaf := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        nil,
			Certificate: [][]byte{[]byte("not a valid certificate DER")},
		},
	}

	certEmpty := certmagic.Certificate{
		Certificate: tls.Certificate{
			Leaf:        nil,
			Certificate: [][]byte{},
		},
	}

	hello := &tls.ClientHelloInfo{}

	t.Run("Pre-parsed Leaf matching SerialNumber", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(100)}},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{certWithLeaf1, certWithLeaf2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(100)) != 0 {
			t.Errorf("expected serial 100, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("On-demand parsing with nil Leaf matching SerialNumber", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(200)}},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeaf1, certNilLeaf2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || !bytesEqual(selected.Certificate.Certificate[0], der2) {
			t.Errorf("expected certNilLeaf2 to be selected")
		}
	})

	t.Run("On-demand parsing with nil Leaf matching SubjectOrganization", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"Org1"},
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeaf1, certNilLeaf2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || !bytesEqual(selected.Certificate.Certificate[0], der1) {
			t.Errorf("expected certNilLeaf1 to be selected")
		}
	})

	t.Run("On-demand parsing with nil Leaf matching PublicKeyAlgorithm", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}
		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeaf1, certNilLeaf2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || !bytesEqual(selected.Certificate.Certificate[0], der1) {
			t.Errorf("expected certNilLeaf1 to be selected")
		}
	})

	t.Run("Safely skip malformed and empty certificates without panic", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(200)}},
		}
		choices := []certmagic.Certificate{certEmpty, certMalformedLeaf, certNilLeaf2}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(selected.Certificate.Certificate) == 0 || !bytesEqual(selected.Certificate.Certificate[0], der2) {
			t.Errorf("expected certNilLeaf2 to be selected")
		}
	})

	t.Run("No match returns error", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(999)}},
		}
		choices := []certmagic.Certificate{certMalformedLeaf, certNilLeaf1}
		_, err := policy.SelectCertificate(hello, choices)
		if err == nil {
			t.Fatalf("expected error when no certificates match, got nil")
		}
	})

	t.Run("Tag selection does not require leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"test-tag"},
		}
		taggedCert := certEmpty
		taggedCert.Tags = []string{"test-tag"}

		selected, err := policy.SelectCertificate(hello, []certmagic.Certificate{certMalformedLeaf, taggedCert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !selected.HasTag("test-tag") {
			t.Errorf("expected tagged cert to be selected")
		}
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
