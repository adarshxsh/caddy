package caddytls

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
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

type testPublisher struct{}

func (testPublisher) PublisherKey() string { return "test" }
func (testPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	return nil
}

func TestRegisterServerNamesConcurrency(t *testing.T) {
	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	tlsApp := &TLS{
		ctx:           caddyCtx,
		serverNames:   make(map[string]serverNameRegistration),
		serverNamesMu: new(sync.Mutex),
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			Publication: []*ECHPublication{
				{
					publishers: []ECHPublisher{testPublisher{}},
				},
			},
		},
	}

	var wg sync.WaitGroup
	const iterations = 500

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tlsApp.RegisterServerNames([]string{fmt.Sprintf("sub%d.example.com", i)}, []string{"h2", "h3"})
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger := zap.NewNop()
		for i := 0; i < iterations; i++ {
			_ = tlsApp.publishECHConfigs(logger)
		}
	}()

	wg.Wait()
}

