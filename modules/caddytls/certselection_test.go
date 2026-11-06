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

func generateTestCert(t *testing.T, serial *big.Int, org string) (certmagic.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  priv,
			Leaf:        parsed,
		},
	}

	return cert, parsed
}

func TestCustomCertSelectionPolicy_SelectCertificate(t *testing.T) {
	cert1, _ := generateTestCert(t, big.NewInt(1001), "Org A")
	cert2, _ := generateTestCert(t, big.NewInt(1002), "Org B")

	cert1NoLeaf := cert1
	cert1NoLeaf.Leaf = nil

	certInvalidDer := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid der bytes")},
		},
	}

	certEmpty := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{},
		},
	}

	helloInfo := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	t.Run("Valid pre-parsed leaf matching serial number", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1001)}},
		}
		selected, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{cert1, cert2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(1001)) != 0 {
			t.Errorf("expected serial 1001, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("Nil leaf pointer dynamically parsed from DER bytes", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1001)}},
		}
		selected, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{cert1NoLeaf, cert2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatal("expected selected certificate Leaf to be populated")
		}
		if selected.Leaf.SerialNumber.Cmp(big.NewInt(1001)) != 0 {
			t.Errorf("expected serial 1001, got %v", selected.Leaf.SerialNumber)
		}
	})

	t.Run("Nil leaf pointer matching organization dynamically parsed", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"Org A"},
		}
		selected, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{cert1NoLeaf, cert2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Leaf == nil {
			t.Fatal("expected selected certificate Leaf to be populated")
		}
		if len(selected.Leaf.Subject.Organization) == 0 || selected.Leaf.Subject.Organization[0] != "Org A" {
			t.Errorf("expected Org A, got %v", selected.Leaf.Subject.Organization)
		}
	})

	t.Run("Nil leaf pointer matching public key algorithm dynamically parsed", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}
		selected, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{cert1NoLeaf})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Leaf == nil || selected.Leaf.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("expected ECDSA algorithm")
		}
	})

	t.Run("Nil leaf pointer with invalid DER bytes skipped safely", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(1001)}},
		}
		// certInvalidDer should be skipped safely without panic
		_, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{certInvalidDer})
		if err == nil {
			t.Fatal("expected error since candidate with invalid DER should be skipped")
		}
	})

	t.Run("Nil leaf pointer with empty certificate slice skipped safely", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"Org A"},
		}
		// certEmpty should be skipped safely without panic
		_, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{certEmpty})
		if err == nil {
			t.Fatal("expected error since candidate with empty certificate slice should be skipped")
		}
	})

	t.Run("Tag selection with nil leaf certificate", func(t *testing.T) {
		taggedCert := cert1NoLeaf
		taggedCert.Tags = []string{"prod"}

		policy := CustomCertSelectionPolicy{
			AllTags: []string{"prod"},
		}
		selected, err := policy.SelectCertificate(helloInfo, []certmagic.Certificate{taggedCert, cert2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !selected.HasTag("prod") {
			t.Errorf("expected certificate with tag 'prod'")
		}
	})
}
