package caddytls

import (
	"context"
	"encoding/base64"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
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
	// nil publicationHistory
	var nilHistory publicationHistory
	if cloned := nilHistory.Clone(); cloned != nil {
		t.Fatalf("expected nil cloned publicationHistory, got %v", cloned)
	}

	t1 := time.Now()
	t2 := t1.Add(time.Minute)

	orig := publicationHistory{
		"pub1": {
			"domain1.com": t1,
		},
		"pub2": nil,
	}

	cloned := orig.Clone()

	// Verify deep copy equality initially
	if !reflect.DeepEqual(cloned["pub1"], orig["pub1"]) {
		t.Fatalf("cloned map mismatch: got %v, want %v", cloned["pub1"], orig["pub1"])
	}

	// Mutate cloned map
	cloned["pub1"]["domain1.com"] = t2
	cloned["pub1"]["domain2.com"] = t2
	cloned["pub3"] = map[string]time.Time{"domain3.com": t2}

	// Verify original is untouched
	if orig["pub1"]["domain1.com"] != t1 {
		t.Fatalf("original timestamp mutated: got %v, want %v", orig["pub1"]["domain1.com"], t1)
	}
	if _, ok := orig["pub1"]["domain2.com"]; ok {
		t.Fatalf("original inner map mutated with domain2.com")
	}
	if _, ok := orig["pub3"]; ok {
		t.Fatalf("original outer map mutated with pub3")
	}
}

func TestECHConfigClone(t *testing.T) {
	t1 := time.Now()
	orig := echConfig{
		ConfigID:      1,
		CipherSuites:  []hpkeSymmetricCipherSuite{{KDFID: 1, AEADID: 1}},
		RawPublicName: "example.com",
		RawExtensions: []byte{0x01, 0x02},
		configBin:     []byte{0x03, 0x04},
		privKeyBin:    []byte{0x05, 0x06},
		meta: echConfigMeta{
			Created: t1,
			Publications: publicationHistory{
				"pub1": {
					"inner.com": t1,
				},
			},
		},
	}

	cloned := orig.Clone()

	// Mutate clone
	cloned.CipherSuites[0].KDFID = 99
	cloned.RawExtensions[0] = 0xff
	cloned.configBin[0] = 0xff
	cloned.privKeyBin[0] = 0xff
	cloned.meta.Publications["pub1"]["inner.com"] = t1.Add(time.Hour)

	// Verify original unchanged
	if orig.CipherSuites[0].KDFID != 1 {
		t.Fatalf("CipherSuites mutated: got %v, want 1", orig.CipherSuites[0].KDFID)
	}
	if orig.RawExtensions[0] != 0x01 {
		t.Fatalf("RawExtensions mutated: got %v, want 1", orig.RawExtensions[0])
	}
	if orig.configBin[0] != 0x03 {
		t.Fatalf("configBin mutated: got %v, want 3", orig.configBin[0])
	}
	if orig.privKeyBin[0] != 0x05 {
		t.Fatalf("privKeyBin mutated: got %v, want 5", orig.privKeyBin[0])
	}
	if orig.meta.Publications["pub1"]["inner.com"] != t1 {
		t.Fatalf("meta.Publications mutated: got %v, want %v", orig.meta.Publications["pub1"]["inner.com"], t1)
	}
}

type mockECHPublisher struct {
	key string
}

func (m *mockECHPublisher) PublisherKey() string {
	return m.key
}

func (m *mockECHPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestECHConfigs_ConcurrentPublishAndRotate(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed to create caddy context: %v", err)
	}

	pubKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	pub := &mockECHPublisher{key: "mockPub"}
	tApp := &TLS{
		ctx: ctx,
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			configs: map[string][]echConfig{
				"example.com": {
					{
						ConfigID:      1,
						PublicKey:     pubKey,
						RawPublicName: "example.com",
						meta: echConfigMeta{
							Created: time.Now(),
							Publications: publicationHistory{
								"mockPub": {
									"inner1.com": time.Now(),
								},
							},
						},
					},
				},
			},
			Publication: []*ECHPublication{
				{
					Configs:    []string{"example.com"},
					Domains:    []string{"inner1.com", "inner2.com"},
					publishers: []ECHPublisher{pub},
				},
			},
		},
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	// Background publishers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = tApp.publishECHConfigs(logger)
			}
		}()
	}

	// Background key rotators / writers
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tApp.EncryptedClientHello.configsMu.Lock()
				cfgs := tApp.EncryptedClientHello.configs["example.com"]
				if len(cfgs) > 0 {
					cfgs[0].meta.Replaced = time.Now()
					newCfg := cfgs[0].Clone()
					newCfg.ConfigID = uint8(j + 2)
					tApp.EncryptedClientHello.configs["example.com"] = append(cfgs, newCfg)
				}
				tApp.EncryptedClientHello.configsMu.Unlock()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Concurrent readers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tApp.EncryptedClientHello.configsMu.RLock()
				_ = len(tApp.EncryptedClientHello.configs["example.com"])
				tApp.EncryptedClientHello.configsMu.RUnlock()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
}
