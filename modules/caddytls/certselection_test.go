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

	"github.com/caddyserver/certmagic"
)

func generateTestCertDER(t *testing.T, serialNumber *big.Int, org string, isRSA bool) ([]byte, *x509.Certificate) {
	t.Helper()
	var priv interface{}
	var pub interface{}
	var pubKeyAlgo x509.PublicKeyAlgorithm

	if isRSA {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		priv = rsaPriv
		pub = &rsaPriv.PublicKey
		pubKeyAlgo = x509.RSA
	} else {
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		priv = ecdsaPriv
		pub = &ecdsaPriv.PublicKey
		pubKeyAlgo = x509.ECDSA
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		PublicKeyAlgorithm: pubKeyAlgo,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}

	return der, leaf
}

func TestSelectCertificateNilLeaf(t *testing.T) {
	sn1 := big.NewInt(12345)
	sn2 := big.NewInt(67890)

	der1, leaf1 := generateTestCertDER(t, sn1, "Acme Corp", false)
	der2, _ := generateTestCertDER(t, sn2, "Beta Inc", true)

	certWithLeaf := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        leaf1,
		},
	}

	certNilLeafValidDER := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        nil,
		},
	}

	certNilLeafRSA := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der2},
			Leaf:        nil,
		},
	}

	certNilLeafCorruptDER := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid der bytes")},
			Leaf:        nil,
		},
	}

	certNilLeafEmptyCert := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{},
			Leaf:        nil,
		},
	}

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}

	t.Run("SerialNumber match with pre-parsed Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *sn1}},
		}
		got, err := policy.SelectCertificate(hello, []certmagic.Certificate{certWithLeaf})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Certificate.Certificate) == 0 || string(got.Certificate.Certificate[0]) != string(der1) {
			t.Errorf("got wrong certificate")
		}
	})

	t.Run("SerialNumber match with nil Leaf and raw DER fallback", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *sn1}},
		}
		got, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeafValidDER})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Certificate.Certificate) == 0 || string(got.Certificate.Certificate[0]) != string(der1) {
			t.Errorf("got wrong certificate")
		}
	})

	t.Run("SubjectOrganization match with nil Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"Acme Corp"},
		}
		got, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeafValidDER})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Certificate.Certificate) == 0 || string(got.Certificate.Certificate[0]) != string(der1) {
			t.Errorf("got wrong certificate")
		}
	})

	t.Run("PublicKeyAlgorithm match with nil Leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}
		got, err := policy.SelectCertificate(hello, []certmagic.Certificate{certNilLeafValidDER})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Certificate.Certificate) == 0 || string(got.Certificate.Certificate[0]) != string(der1) {
			t.Errorf("got wrong certificate")
		}
	})

	t.Run("Skip corrupt DER and empty certificate safely without panic", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *sn1}},
		}
		choices := []certmagic.Certificate{
			certNilLeafCorruptDER,
			certNilLeafEmptyCert,
			certNilLeafValidDER,
		}
		got, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Certificate.Certificate) == 0 || string(got.Certificate.Certificate[0]) != string(der1) {
			t.Errorf("got wrong certificate")
		}
	})

	t.Run("No match returns error when all choices are unparseable or non-matching", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *sn1}},
		}
		choices := []certmagic.Certificate{
			certNilLeafCorruptDER,
			certNilLeafEmptyCert,
			certNilLeafRSA,
		}
		_, err := policy.SelectCertificate(hello, choices)
		if err == nil {
			t.Fatalf("expected error when no certificates match, got nil")
		}
	})

	t.Run("Tag selection with nil Leaf and empty certificate", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			AnyTag: []string{"test-tag"},
		}
		taggedCert := certmagic.Certificate{
			Certificate: tls.Certificate{
				Certificate: [][]byte{},
				Leaf:        nil,
			},
			Tags: []string{"test-tag"},
		}
		got, err := policy.SelectCertificate(hello, []certmagic.Certificate{taggedCert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.HasTag("test-tag") {
			t.Errorf("expected tagged cert to be selected")
		}
	})
}
