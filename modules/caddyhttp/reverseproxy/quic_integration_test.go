package reverseproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type quicErrorReader struct {
	data      []byte
	err       error
	readBytes int
}

func (r *quicErrorReader) Read(p []byte) (int, error) {
	if r.readBytes < len(r.data) {
		n := copy(p, r.data[r.readBytes:])
		r.readBytes += n
		return n, nil
	}
	return 0, r.err
}

func (r *quicErrorReader) Close() error {
	return nil
}

func generateTLSConfig(t *testing.T) *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Caddy Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load x509 key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}

func TestHTTP3StreamResetPropagation(t *testing.T) {
	// Create UDP socket for HTTP/3 server
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer udpConn.Close()

	tlsConf := generateTLSConfig(t)

	// Custom handler simulating Caddy reverse proxy responding to downstream client
	h := Handler{
		logger: caddy.Log(),
	}

	const expectedErrorCode quic.StreamErrorCode = 0x10c

	proxyHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		res := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: &quicErrorReader{
				data: []byte("partial response body bytes"),
				err:  &quic.StreamError{ErrorCode: expectedErrorCode},
			},
		}

		defer func() {
			r := recover()
			if r != http.ErrAbortHandler {
				t.Errorf("expected panic(http.ErrAbortHandler), got %v", r)
			}
		}()

		rw.WriteHeader(res.StatusCode)
		err := h.copyResponse(rw, res.Body, 0, caddy.Log())
		if err != nil {
			fields := []zap.Field{zap.Error(err)}
			if code, ok := extractQUICErrorCode(err); ok {
				fields = append(fields, zap.Uint64("quic_error_code", uint64(code)))
				if streamer := findHTTPStreamer(rw); streamer != nil {
					if stream := streamer.HTTPStream(); stream != nil {
						stream.CancelWrite(code)
						stream.CancelRead(code)
					}
				}
			}
			panic(http.ErrAbortHandler)
		}
	})

	server := &http3.Server{
		Handler:   proxyHandler,
		TLSConfig: tlsConf,
	}

	go func() {
		_ = server.Serve(udpConn)
	}()
	defer server.Close()

	// Setup HTTP/3 client
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer tr.Close()

	client := &http.Client{
		Transport: tr,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", udpConn.LocalAddr().String()), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Note: The error could occur during Do or during Body.Read
		var strErr *quic.StreamError
		if errors.As(err, &strErr) {
			if strErr.ErrorCode != expectedErrorCode {
				t.Fatalf("expected stream error code %#x, got %#x", expectedErrorCode, strErr.ErrorCode)
			}
			return
		}
		var h3Err *http3.Error
		if errors.As(err, &h3Err) {
			if quic.StreamErrorCode(h3Err.ErrorCode) != expectedErrorCode {
				t.Fatalf("expected h3 error code %#x, got %#x", expectedErrorCode, h3Err.ErrorCode)
			}
			return
		}
	} else {
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		if err == nil {
			t.Fatal("expected error reading response body, got nil")
		}
		var strErr *quic.StreamError
		if errors.As(err, &strErr) {
			if strErr.ErrorCode != expectedErrorCode {
				t.Fatalf("expected stream error code %#x, got %#x", expectedErrorCode, strErr.ErrorCode)
			}
			return
		}
		var h3Err *http3.Error
		if errors.As(err, &h3Err) {
			if quic.StreamErrorCode(h3Err.ErrorCode) != expectedErrorCode {
				t.Fatalf("expected h3 error code %#x, got %#x", expectedErrorCode, h3Err.ErrorCode)
			}
			return
		}
		t.Fatalf("expected quic.StreamError or http3.Error, got %v (%T)", err, err)
	}
}
