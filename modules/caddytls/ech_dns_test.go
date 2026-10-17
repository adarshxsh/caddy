package caddytls

import (
	"context"
	"encoding/base64"
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
	// 1. Nil map
	var nilPH publicationHistory
	if cloned := nilPH.clone(); cloned != nil {
		t.Fatalf("expected nil clone for nil publicationHistory, got %#v", cloned)
	}

	// 2. Empty map
	emptyPH := make(publicationHistory)
	clonedEmpty := emptyPH.clone()
	if clonedEmpty == nil || len(clonedEmpty) != 0 {
		t.Fatalf("expected empty non-nil map, got %#v", clonedEmpty)
	}

	// 3. Deep copy check
	now := time.Now()
	orig := publicationHistory{
		"pub1": {
			"example.com": now,
		},
		"pub2": nil,
	}

	cloned := orig.clone()
	if !reflect.DeepEqual(cloned, orig) {
		t.Fatalf("cloned map not equal to original: got %#v want %#v", cloned, orig)
	}

	// Mutate clone and verify original is unchanged
	cloned["pub1"]["example.com"] = now.Add(time.Hour)
	cloned["pub1"]["sub.example.com"] = now
	cloned["pub3"] = map[string]time.Time{"other.com": now}

	if orig["pub1"]["example.com"].Equal(now.Add(time.Hour)) {
		t.Fatalf("mutating clone modified original timestamp")
	}
	if _, ok := orig["pub1"]["sub.example.com"]; ok {
		t.Fatalf("mutating clone added key to original map")
	}
	if _, ok := orig["pub3"]; ok {
		t.Fatalf("mutating clone added publisher to original map")
	}
}

type mockECHPublisher struct {
	key string
}

func (m *mockECHPublisher) PublisherKey() string {
	return m.key
}

func (m *mockECHPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(100 * time.Microsecond)
	return nil
}

func TestECHPublicationConcurrentRotation(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	mockPub := &mockECHPublisher{key: "mock_pub"}
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   make(map[string][]echConfig),
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{mockPub},
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

	now := time.Now()
	cfg1, err := generateAndStoreECHConfig(caddyCtx, "example.com")
	if err != nil {
		t.Fatalf("failed generating ech config for test: %v", err)
	}
	cfg1.meta.Publications = publicationHistory{
		"mock_pub": map[string]time.Time{
			"sub.example.com": now,
		},
	}
	ech.configs["example.com"] = []echConfig{cfg1}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutines calling publishECHConfigs
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger := zap.NewNop()
			for {
				select {
				case <-stop:
					return
				default:
					_ = tlsApp.publishECHConfigs(logger)
				}
			}
		}()
	}

	// Goroutines modifying configs / metadata concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ech.configsMu.Lock()
					if cfgs, ok := ech.configs["example.com"]; ok && len(cfgs) > 0 {
						cfgs[0].meta.Created = time.Now()
						if cfgs[0].meta.Publications != nil {
							cfgs[0].meta.Publications["mock_pub"] = map[string]time.Time{
								"sub.example.com": time.Now(),
							}
						}
					}
					ech.configsMu.Unlock()
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

