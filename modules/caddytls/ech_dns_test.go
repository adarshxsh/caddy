package caddytls

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

func TestRegisterServerNamesWithALPN(t *testing.T) {
	tlsApp := &TLS{
		serverNames: make(map[string]serverNameRegistration),
	}

	tlsApp.RegisterServerNames([]string{
		"Example.com:443",
		"example.com",
		"127.0.0.1:443",
	}, []string{"h2", "http/1.1"})
	tlsApp.RegisterServerNames([]string{"EXAMPLE.COM"}, []string{"h3"})

	got := tlsApp.alpnValuesForServerNames([]string{"example.com:443", "127.0.0.1:443"})
	want := map[string][]string{
		"example.com": {"h3", "h2", "http/1.1"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ALPN values: got %#v want %#v", got, want)
	}
}

func TestServerNamesConcurrency(t *testing.T) {
	tlsApp := &TLS{
		serverNames: make(map[string]serverNameRegistration),
	}

	// Verify uninitialized/empty TLS handles ServerNames safely
	emptyTLS := &TLS{}
	if names := emptyTLS.ServerNames(); names == nil || len(names) != 0 {
		t.Fatalf("expected empty non-nil slice from uninitialized TLS, got: %#v", names)
	}

	var wg sync.WaitGroup
	numGoroutines := 20
	iterations := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(3)

		// Goroutine 1: RegisterServerNames
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				domain := fmt.Sprintf("sub%d-%d.example.com", id, j)
				tlsApp.RegisterServerNames([]string{domain}, []string{"h2", "h3"})
			}
		}(i)

		// Goroutine 2: ServerNames
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tlsApp.ServerNames()
			}
		}()

		// Goroutine 3: alpnValuesForServerNames
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				domain := fmt.Sprintf("sub%d-%d.example.com", id, j)
				_ = tlsApp.alpnValuesForServerNames([]string{domain})
			}
		}(i)
	}

	wg.Wait()

	names := tlsApp.ServerNames()
	if len(names) == 0 {
		t.Fatalf("expected registered server names, got empty slice")
	}
}

func TestECHDNSPublisherPublishedSvcParams(t *testing.T) {
	dnsPub := &ECHDNSPublisher{
		alpnByDomain: map[string][]string{
			"example.com": {"h3", "h2", "http/1.1"},
		},
	}

	existing := libdns.SvcParams{
		"alpn":     {"h2"},
		"ipv4hint": {"203.0.113.10"},
	}

	got := dnsPub.publishedSvcParams("Example.com", existing, []byte{0x01, 0x02, 0x03})

	if !reflect.DeepEqual(existing["alpn"], []string{"h2"}) {
		t.Fatalf("existing params mutated: got %v", existing["alpn"])
	}

	if !reflect.DeepEqual(got["alpn"], []string{"h3", "h2", "http/1.1"}) {
		t.Fatalf("unexpected ALPN params: got %v", got["alpn"])
	}

	if !reflect.DeepEqual(got["ipv4hint"], []string{"203.0.113.10"}) {
		t.Fatalf("unexpected preserved params: got %v", got["ipv4hint"])
	}

	wantECH := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	if !reflect.DeepEqual(got["ech"], []string{wantECH}) {
		t.Fatalf("unexpected ECH params: got %v want %v", got["ech"], wantECH)
	}
}
