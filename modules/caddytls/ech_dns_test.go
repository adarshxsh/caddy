package caddytls

import (
	"context"
	"encoding/base64"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
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

func TestECHConfigClone(t *testing.T) {
	var nilHistory publicationHistory
	if nilHistory.clone() != nil {
		t.Fatalf("expected nil clone for nil publicationHistory")
	}

	pubTime := time.Now()
	originalHistory := publicationHistory{
		"pub1": {
			"example.com": pubTime,
		},
	}
	clonedHistory := originalHistory.clone()
	clonedHistory["pub1"]["example.com"] = pubTime.Add(time.Hour)
	clonedHistory["pub2"] = map[string]time.Time{"domain2.com": pubTime}

	if originalHistory["pub1"]["example.com"].Equal(clonedHistory["pub1"]["example.com"]) {
		t.Fatalf("mutation on cloned publicationHistory affected original")
	}
	if _, ok := originalHistory["pub2"]; ok {
		t.Fatalf("new key in cloned publicationHistory leaked to original")
	}

	origCfg := echConfig{
		ConfigID:      42,
		RawPublicName: "example.com",
		CipherSuites:  []hpkeSymmetricCipherSuite{{KDFID: 1, AEADID: 1}},
		RawExtensions: []byte{0x01, 0x02},
		configBin:     []byte{0x03, 0x04},
		privKeyBin:    []byte{0x05, 0x06},
		meta: echConfigMeta{
			Created:      pubTime,
			Publications: originalHistory.clone(),
		},
	}

	clonedCfg := origCfg.clone()
	clonedCfg.meta.Publications["pub1"]["example.com"] = pubTime.Add(2 * time.Hour)
	clonedCfg.CipherSuites[0].KDFID = 99
	clonedCfg.RawExtensions[0] = 0xff

	if origCfg.meta.Publications["pub1"]["example.com"].Equal(clonedCfg.meta.Publications["pub1"]["example.com"]) {
		t.Fatalf("mutation on cloned cfg.meta affected origCfg")
	}
	if origCfg.CipherSuites[0].KDFID == 99 {
		t.Fatalf("mutation on cloned CipherSuites affected origCfg")
	}
	if origCfg.RawExtensions[0] == 0xff {
		t.Fatalf("mutation on cloned RawExtensions affected origCfg")
	}
}

type mockTestPublisher struct {
	key string
}

func (m *mockTestPublisher) PublisherKey() string {
	return m.key
}

func (m *mockTestPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(10 * time.Microsecond)
	return nil
}

func TestConcurrentECHPublicationMapSafety(t *testing.T) {
	tmpDir := t.TempDir()
	origDefaultStorage := caddy.DefaultStorage
	caddy.DefaultStorage = &certmagic.FileStorage{Path: tmpDir}
	defer func() {
		caddy.DefaultStorage = origDefaultStorage
	}()

	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	cfg1, err := generateAndStoreECHConfig(caddyCtx, "example.com")
	if err != nil {
		t.Fatalf("generateAndStoreECHConfig failed: %v", err)
	}

	pub := &mockTestPublisher{key: "testPublisher"}
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {cfg1},
		},
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{pub},
				Domains:    []string{"example.com"},
			},
		},
	}

	tlsApp := &TLS{
		ctx:                  caddyCtx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutine 1: Background publication
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = tlsApp.publishECHConfigs(zap.NewNop())
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()

	// Goroutine 2: Simulated key rotation / updates under Lock()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				newCfg, genErr := generateAndStoreECHConfig(caddyCtx, "example.com")
				if genErr != nil {
					continue
				}
				ech.configsMu.Lock()
				if len(ech.configs["example.com"]) > 0 {
					ech.configs["example.com"][0].meta.Replaced = time.Now()
					ech.configs["example.com"] = append(ech.configs["example.com"], newCfg)
					if len(ech.configs["example.com"]) > 3 {
						ech.configs["example.com"] = ech.configs["example.com"][1:]
					}
				}
				ech.configsMu.Unlock()
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	// Goroutine 3: Readers under RLock()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				ech.configsMu.RLock()
				for _, cfgs := range ech.configs {
					for _, cfg := range cfgs {
						_ = cfg.meta.Publications["testPublisher"]["example.com"]
					}
				}
				ech.configsMu.RUnlock()
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
