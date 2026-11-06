package caddytls

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
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
	var nilPH publicationHistory
	if got := nilPH.Clone(); got != nil {
		t.Fatalf("expected nil for nil publicationHistory clone, got %#v", got)
	}

	t1 := time.Now().Add(-1 * time.Hour)
	t2 := time.Now()
	original := publicationHistory{
		"pub1": {
			"example.com": t1,
		},
		"pub2": nil,
	}

	cloned := original.Clone()
	if !reflect.DeepEqual(original, cloned) {
		t.Fatalf("cloned map differs from original: got %#v want %#v", cloned, original)
	}

	// Mutate cloned map and ensure original is untouched
	cloned["pub1"]["example.com"] = t2
	cloned["pub1"]["other.com"] = t2
	cloned["pub3"] = map[string]time.Time{"new.com": t2}

	if original["pub1"]["example.com"].Equal(t2) {
		t.Fatal("original map inner value was mutated by clone modification")
	}
	if _, ok := original["pub1"]["other.com"]; ok {
		t.Fatal("original map inner entry was mutated by clone addition")
	}
	if _, ok := original["pub3"]; ok {
		t.Fatal("original map outer entry was mutated by clone addition")
	}
}

func TestECHConfigClone(t *testing.T) {
	t1 := time.Now()
	cfg := echConfig{
		ConfigID:      42,
		RawPublicName: "public.example.com",
		configBin:     []byte{1, 2, 3},
		privKeyBin:    []byte{4, 5, 6},
		RawExtensions: []byte{7, 8, 9},
		CipherSuites: []hpkeSymmetricCipherSuite{
			{KDFID: 1, AEADID: 1},
		},
		meta: echConfigMeta{
			Created: t1,
			Publications: publicationHistory{
				"pub1": {
					"inner.example.com": t1,
				},
			},
		},
	}

	cloned := cfg.Clone()

	// Mutate cloned byte slices and maps
	cloned.configBin[0] = 99
	cloned.privKeyBin[0] = 99
	cloned.RawExtensions[0] = 99
	cloned.CipherSuites[0].KDFID = 99
	cloned.meta.Publications["pub1"]["inner.example.com"] = t1.Add(time.Hour)

	if cfg.configBin[0] == 99 {
		t.Fatal("original configBin was mutated")
	}
	if cfg.privKeyBin[0] == 99 {
		t.Fatal("original privKeyBin was mutated")
	}
	if cfg.RawExtensions[0] == 99 {
		t.Fatal("original RawExtensions was mutated")
	}
	if cfg.CipherSuites[0].KDFID == 99 {
		t.Fatal("original CipherSuites was mutated")
	}
	if cfg.meta.Publications["pub1"]["inner.example.com"].Equal(t1.Add(time.Hour)) {
		t.Fatal("original meta.Publications was mutated")
	}
}

type dummyPublisher struct {
	key string
}

func (d dummyPublisher) PublisherKey() string {
	return d.key
}

func (d dummyPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	return nil
}

func TestPublishECHConfigsConcurrentWithRotation(t *testing.T) {
	tmpStorage := &certmagic.FileStorage{Path: t.TempDir()}
	certmagic.Default.Storage = tmpStorage

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	logger := zap.NewNop()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{
					dummyPublisher{key: "dummy_pub"},
				},
			},
		},
	}

	publicName := "public.example.com"
	echCfg1, err := generateAndStoreECHConfig(caddyCtx, publicName)
	if err != nil {
		t.Fatalf("failed to generate ECH config: %v", err)
	}
	echCfg1.meta.Created = time.Now().Add(-24 * time.Hour * 31)
	metaBytes, _ := json.Marshal(echCfg1.meta)
	_ = tmpStorage.Store(caddyCtx, echMetaKey(echCfg1.ConfigID), metaBytes)

	ech.configs[publicName] = []echConfig{echCfg1}
	ech.updateKeyList()

	tlsApp := &TLS{
		ctx:                  caddyCtx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"inner.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	var wg sync.WaitGroup
	workers := 10
	iterations := 20

	for w := 0; w < workers; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tlsApp.EncryptedClientHello.configsMu.Lock()
				_ = tlsApp.EncryptedClientHello.rotateECHKeys(caddyCtx, logger, false)
				tlsApp.EncryptedClientHello.configsMu.Unlock()
			}
		}()
	}

	wg.Wait()
}
