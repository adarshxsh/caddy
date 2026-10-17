package caddytls

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/libdns/libdns"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestRegisterServerNamesWithALPN(t *testing.T) {
	tlsApp := &TLS{
		serverNames:   make(map[string]serverNameRegistration),
		serverNamesMu: new(sync.Mutex),
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

func TestPublishECHConfigsConcurrentRegisterServerNames(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tlsApp := &TLS{
		ctx:           ctx,
		serverNames:   make(map[string]serverNameRegistration),
		serverNamesMu: new(sync.Mutex),
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			Publication: []*ECHPublication{
				{
					Domains: nil, // force publishECHConfigs to snapshot t.serverNames
				},
			},
		},
	}

	logger := zap.NewNop()

	var wg sync.WaitGroup
	const iterations = 200

	// Writer goroutine: concurrently registers server names
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tlsApp.RegisterServerNames(
				[]string{fmt.Sprintf("domain%d.com", i), fmt.Sprintf("sub%d.example.com", i)},
				[]string{"h2", "h3"},
			)
		}
	}()

	// Reader goroutine: concurrently publishes ECH configs which reads server names snapshot
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = tlsApp.publishECHConfigs(logger)
		}
	}()

	wg.Wait()
}
