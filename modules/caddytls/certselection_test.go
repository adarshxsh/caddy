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

func createTestCertDerAndLeaf(t *testing.T, serial int64, org string, keyAlgo string) ([]byte, *x509.Certificate) {
	t.Helper()

	var priv any
	var err error
	if keyAlgo == "rsa" {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}

	var pub any
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return derBytes, leaf
}

func TestCustomCertSelectionPolicy_SelectCertificate(t *testing.T) {
	der1, leaf1 := createTestCertDerAndLeaf(t, 100, "OrgA", "ecdsa")
	der2, _ := createTestCertDerAndLeaf(t, 200, "OrgB", "rsa")

	// Choice 1: cert.Leaf is nil, valid DER bytes (OrgA, SN 100, ECDSA)
	cert1 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        nil,
		},
		Tags: []string{"tagA"},
	}

	// Choice 2: cert.Leaf is nil, valid DER bytes (OrgB, SN 200, RSA)
	cert2 := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der2},
			Leaf:        nil,
		},
		Tags: []string{"tagB"},
	}

	// Choice 3: cert.Leaf is nil, empty Certificate bytes
	cert3Empty := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: nil,
			Leaf:        nil,
		},
		Tags: []string{"tagEmpty"},
	}

	// Choice 4: cert.Leaf is nil, invalid DER bytes
	cert4Invalid := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("invalid der bytes")},
			Leaf:        nil,
		},
		Tags: []string{"tagInvalid"},
	}

	// Choice 5: cert.Leaf is pre-parsed
	cert5Preparsed := certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der1},
			Leaf:        leaf1,
		},
		Tags: []string{"tagPreparsed"},
	}

	hello := &tls.ClientHelloInfo{}

	t.Run("SerialNumber filter lazy parsing and nil guard", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(100)}},
		}

		// choices with nil Leaf, empty bytes, invalid bytes
		choices := []certmagic.Certificate{cert3Empty, cert4Invalid, cert2, cert1}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagA" {
			t.Errorf("expected tagA, got %v", selected.Tags)
		}

		// non-matching serial number
		policyNoMatch := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(999)}},
		}
		_, err = policyNoMatch.SelectCertificate(hello, choices)
		if err == nil {
			t.Errorf("expected error when no certificates match serial number, got nil")
		}
	})

	t.Run("SubjectOrganization filter lazy parsing and nil guard", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgB"},
		}

		choices := []certmagic.Certificate{cert3Empty, cert4Invalid, cert1, cert2}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagB" {
			t.Errorf("expected tagB, got %v", selected.Tags)
		}

		policyNoMatch := CustomCertSelectionPolicy{
			SubjectOrganization: []string{"OrgC"},
		}
		_, err = policyNoMatch.SelectCertificate(hello, choices)
		if err == nil {
			t.Errorf("expected error when no certificates match organization, got nil")
		}
	})

	t.Run("PublicKeyAlgorithm filter lazy parsing and nil guard", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
		}

		choices := []certmagic.Certificate{cert3Empty, cert4Invalid, cert2, cert1}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagA" {
			t.Errorf("expected tagA, got %v", selected.Tags)
		}

		policyRSA := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.RSA),
		}
		selectedRSA, err := policyRSA.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selectedRSA.Tags[0] != "tagB" {
			t.Errorf("expected tagB, got %v", selectedRSA.Tags)
		}

		policyDSA := CustomCertSelectionPolicy{
			PublicKeyAlgorithm: PublicKeyAlgorithm(x509.DSA),
		}
		_, err = policyDSA.SelectCertificate(hello, choices)
		if err == nil {
			t.Errorf("expected error when no certificates match algorithm, got nil")
		}
	})

	t.Run("Tag filtering without leaf metadata", func(t *testing.T) {
		policyAny := CustomCertSelectionPolicy{
			AnyTag: []string{"tagEmpty"},
		}
		choices := []certmagic.Certificate{cert4Invalid, cert3Empty, cert1}
		selected, err := policyAny.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagEmpty" {
			t.Errorf("expected tagEmpty, got %v", selected.Tags)
		}

		policyAll := CustomCertSelectionPolicy{
			AllTags: []string{"tagInvalid"},
		}
		selectedAll, err := policyAll.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selectedAll.Tags[0] != "tagInvalid" {
			t.Errorf("expected tagInvalid, got %v", selectedAll.Tags)
		}
	})

	t.Run("Preparsed cert.Leaf preserved", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber: []bigInt{{Int: *big.NewInt(100)}},
		}
		choices := []certmagic.Certificate{cert5Preparsed}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagPreparsed" {
			t.Errorf("expected tagPreparsed, got %v", selected.Tags)
		}
	})

	t.Run("Combined selection policy with unparsed leaf", func(t *testing.T) {
		policy := CustomCertSelectionPolicy{
			SerialNumber:        []bigInt{{Int: *big.NewInt(100)}},
			SubjectOrganization: []string{"OrgA"},
			PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.ECDSA),
			AnyTag:              []string{"tagA"},
			AllTags:             []string{"tagA"},
		}
		choices := []certmagic.Certificate{cert3Empty, cert4Invalid, cert2, cert1}
		selected, err := policy.SelectCertificate(hello, choices)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected.Tags[0] != "tagA" {
			t.Errorf("expected tagA, got %v", selected.Tags)
		}
	})
}
