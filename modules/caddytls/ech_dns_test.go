package caddytls

import (
	"context"
	"encoding/base64"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

type mockPublisher struct {
	key string
}

func (m *mockPublisher) PublisherKey() string {
	return m.key
}

func (m *mockPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	return nil
}

func TestPublicationHistoryClone(t *testing.T) {
	var nilPH publicationHistory
	if cloned := nilPH.Clone(); cloned != nil {
		t.Fatalf("expected nil clone for nil publicationHistory, got %v", cloned)
	}

	now := time.Now()
	ph := publicationHistory{
		"pub1": map[string]time.Time{
			"example.com": now,
		},
		"pub2": nil,
	}

	cloned := ph.Clone()

	cloned["pub1"]["example.com"] = now.Add(time.Hour)
	cloned["pub3"] = map[string]time.Time{"other.com": now}

	if ph["pub1"]["example.com"].Equal(cloned["pub1"]["example.com"]) {
		t.Fatalf("expected original publicationHistory not to be mutated by cloned map changes")
	}
	if _, ok := ph["pub3"]; ok {
		t.Fatalf("expected pub3 not to be present in original map")
	}
}

func TestECHConfigClone(t *testing.T) {
	now := time.Now()
	cfg := echConfig{
		ConfigID:      42,
		RawPublicName: "public.example.com",
		CipherSuites:  []hpkeSymmetricCipherSuite{{KDFID: 1, AEADID: 2}},
		RawExtensions: []byte{1, 2, 3},
		configBin:     []byte{4, 5, 6},
		privKeyBin:    []byte{7, 8, 9},
		meta: echConfigMeta{
			Created: now,
			Publications: publicationHistory{
				"pub1": map[string]time.Time{
					"inner.example.com": now,
				},
			},
		},
	}

	cloned := cfg.Clone()

	if cloned.ConfigID != cfg.ConfigID || cloned.RawPublicName != cfg.RawPublicName {
		t.Fatalf("cloned struct scalar mismatch")
	}

	cloned.CipherSuites[0].KDFID = 99
	cloned.RawExtensions[0] = 99
	cloned.configBin[0] = 99
	cloned.privKeyBin[0] = 99
	cloned.meta.Publications["pub1"]["inner.example.com"] = now.Add(time.Hour)

	if cfg.CipherSuites[0].KDFID == 99 {
		t.Fatalf("original CipherSuites mutated")
	}
	if cfg.RawExtensions[0] == 99 {
		t.Fatalf("original RawExtensions mutated")
	}
	if cfg.configBin[0] == 99 {
		t.Fatalf("original configBin mutated")
	}
	if cfg.privKeyBin[0] == 99 {
		t.Fatalf("original privKeyBin mutated")
	}
	if cfg.meta.Publications["pub1"]["inner.example.com"].Equal(now.Add(time.Hour)) {
		t.Fatalf("original Publications mutated")
	}
}

func TestConcurrentECHPublicationAndRotation(t *testing.T) {
	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed to provision context: %v", err)
	}

	cfg1, err := generateAndStoreECHConfig(caddyCtx, "example.com")
	if err != nil {
		t.Fatalf("failed to generate ech config 1: %v", err)
	}
	cfg2, err := generateAndStoreECHConfig(caddyCtx, "example.com")
	if err != nil {
		t.Fatalf("failed to generate ech config 2: %v", err)
	}

	pub := &mockPublisher{key: "mock_publisher"}
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {cfg1, cfg2},
		},
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{pub},
			},
		},
	}

	tlsApp := &TLS{
		ctx:                  caddyCtx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"sub.example.com": {},
		},
	}

	var wg sync.WaitGroup
	workers := 10
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if id%2 == 0 {
					_ = tlsApp.publishECHConfigs(zap.NewNop())
				} else {
					ech.configsMu.Lock()
					for name, cfgs := range ech.configs {
						for idx := range cfgs {
							if ech.configs[name][idx].meta.Publications == nil {
								ech.configs[name][idx].meta.Publications = make(publicationHistory)
							}
							ech.configs[name][idx].meta.Publications["mock_publisher"] = map[string]time.Time{
								"sub.example.com": time.Now(),
							}
						}
					}
					ech.updateKeyList()
					ech.configsMu.Unlock()
				}
			}
		}(w)
	}

	wg.Wait()
}

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
