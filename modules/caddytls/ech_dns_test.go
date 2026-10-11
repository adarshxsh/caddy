package caddytls

import (
	"encoding/base64"
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

func TestServerNamesConcurrency(t *testing.T) {
	tlsApp := &TLS{
		serverNames: make(map[string]serverNameRegistration),
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutine calling RegisterServerNames concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tlsApp.RegisterServerNames([]string{"example.com", "sub.example.com"}, []string{"h2", "h3"})
			}
		}
	}()

	// Reader goroutines calling ServerNames and alpnValuesForServerNames concurrently
	var readersWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		readersWg.Add(1)
		go func() {
			defer readersWg.Done()
			for j := 0; j < 500; j++ {
				names := tlsApp.ServerNames()
				_ = tlsApp.alpnValuesForServerNames(names)
			}
		}()
	}

	readersWg.Wait()
	close(stop)
	wg.Wait()
}

func TestServerNamesNilMap(t *testing.T) {
	tlsApp := &TLS{}
	names := tlsApp.ServerNames()
	if names == nil {
		t.Fatalf("expected non-nil slice, got nil")
	}
	if len(names) != 0 {
		t.Fatalf("expected empty slice, got len %d", len(names))
	}
}
