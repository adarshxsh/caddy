package caddytls

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

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

func TestPublicationHistoryClone(t *testing.T) {
	// Test nil
	var nilPH publicationHistory
	if cloned := nilPH.Clone(); cloned != nil {
		t.Fatalf("expected nil clone for nil publicationHistory, got %v", cloned)
	}

	// Test populated map
	now := time.Now()
	ph := publicationHistory{
		"pub1": map[string]time.Time{
			"domain1": now,
		},
		"pub2": nil,
	}

	cloned := ph.Clone()
	if !reflect.DeepEqual(cloned, ph) {
		t.Fatalf("cloned map not equal: got %#v want %#v", cloned, ph)
	}

	// Mutate clone and verify original is unaffected
	cloned["pub1"]["domain2"] = now
	if _, ok := ph["pub1"]["domain2"]; ok {
		t.Fatalf("mutation of clone leaked to original map")
	}
}

type mockPublisher struct {
	key     string
	pubFunc func(ctx context.Context, innerNames []string, echConfigList []byte) error
}

func (m *mockPublisher) PublisherKey() string {
	if m.key != "" {
		return m.key
	}
	return "mock"
}

func (m *mockPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	if m.pubFunc != nil {
		return m.pubFunc(ctx, innerNames, echConfigList)
	}
	return nil
}

func TestECHPublicationAndRotationRace(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &caddy.Config{
		StorageRaw: json.RawMessage(fmt.Sprintf(`{"module":"file_system","root":%q}`, tmpDir)),
	}

	caddyCtx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext error: %v", err)
	}

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{
					&mockPublisher{
						key: "mockPublisher",
						pubFunc: func(ctx context.Context, innerNames []string, echConfigList []byte) error {
							time.Sleep(1 * time.Millisecond)
							return nil
						},
					},
				},
			},
		},
	}

	outerNames, err := ech.Provision(caddyCtx)
	if err != nil {
		t.Fatalf("Provision error: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outerNames, got 0")
	}

	tlsApp := &TLS{
		ctx:                  caddyCtx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"inner.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	logger := zap.NewNop()

	var wg sync.WaitGroup
	workers := 8
	iterations := 15

	// Concurrent publications
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
	}

	// Concurrent key rotations and reads
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				ech.configsMu.Lock()
				_ = ech.rotateECHKeys(caddyCtx, logger, true)
				ech.configsMu.Unlock()

				ech.configsMu.RLock()
				_ = len(ech.stdlibReady)
				for _, cfgs := range ech.configs {
					for _, c := range cfgs {
						_ = c.meta.Publications.Clone()
					}
				}
				ech.configsMu.RUnlock()
			}
		}()
	}

	wg.Wait()
}
