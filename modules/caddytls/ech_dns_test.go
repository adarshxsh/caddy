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
		serverNamesMu: new(sync.RWMutex),
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

type dummyPublisher struct{}

func (dummyPublisher) PublisherKey() string { return "dummy" }
func (dummyPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	return nil
}

func TestConcurrentRegisterServerNamesAndPublishECH(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatal(err)
	}

	tlsApp := &TLS{
		ctx:           ctx,
		serverNames:   make(map[string]serverNameRegistration),
		serverNamesMu: new(sync.RWMutex),
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			Publication: []*ECHPublication{
				{
					publishers: []ECHPublisher{dummyPublisher{}},
				},
			},
		},
	}

	var wg sync.WaitGroup
	const numGoroutines = 10
	const iterations = 100

	// Concurrent writers registering server names
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				domain := fmt.Sprintf("sub%d-%d.example.com", id, j)
				tlsApp.RegisterServerNames([]string{domain}, []string{"h2", "http/1.1"})
			}
		}(i)
	}

	// Concurrent readers running publishECHConfigs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger := zap.NewNop()
			for j := 0; j < iterations; j++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
	}

	wg.Wait()
}

