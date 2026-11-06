package caddytls

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestPublicationHistoryClone(t *testing.T) {
	var nilPH publicationHistory
	if cloned := nilPH.Clone(); cloned != nil {
		t.Fatalf("expected nil clone for nil publicationHistory, got %v", cloned)
	}

	ph := publicationHistory{
		"pub1": {
			"domain1": time.Now(),
		},
		"pub2": nil,
	}

	cloned := ph.Clone()
	if len(cloned) != len(ph) {
		t.Fatalf("expected length %d, got %d", len(ph), len(cloned))
	}

	// Mutate clone and verify original is unchanged
	cloned["pub1"]["domain1"] = time.Time{}
	cloned["pub1"]["domain2"] = time.Now()
	cloned["pub3"] = map[string]time.Time{"domain3": time.Now()}

	if _, exists := ph["pub1"]["domain2"]; exists {
		t.Errorf("mutation in cloned map leaked to original map")
	}
	if _, exists := ph["pub3"]; exists {
		t.Errorf("mutation in cloned map leaked to original map")
	}
}

func TestECHConfigClone(t *testing.T) {
	now := time.Now()
	cfg := echConfig{
		ConfigID:      42,
		RawPublicName: "example.com",
		meta: echConfigMeta{
			Created: now,
			Publications: publicationHistory{
				"pub1": {
					"inner1": now,
				},
			},
		},
	}

	cloned := cfg.Clone()
	if cloned.ConfigID != cfg.ConfigID || cloned.RawPublicName != cfg.RawPublicName {
		t.Fatalf("cloned echConfig scalar fields mismatch")
	}

	cloned.meta.Publications["pub1"]["inner1"] = time.Time{}
	if cfg.meta.Publications["pub1"]["inner1"].Equal(time.Time{}) {
		t.Errorf("modifying cloned echConfig Publications modified original")
	}
}

type mockPublisher struct {
	key string
}

func (m *mockPublisher) PublisherKey() string {
	return m.key
}

func (m *mockPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestECHPublicationConcurrency(t *testing.T) {
	var cfg caddy.Config
	caddyCtx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	publisher := &mockPublisher{key: "mock_pub"}
	pub := &ECHPublication{
		publishers: []ECHPublisher{publisher},
		Domains:    []string{"app.example.com", "api.example.com"},
	}

	tlsApp := &TLS{
		ctx: caddyCtx,
		EncryptedClientHello: &ECH{
			configsMu: new(sync.RWMutex),
			configs:   make(map[string][]echConfig),
			Publication: []*ECHPublication{pub},
		},
		serverNames: map[string]serverNameRegistration{
			"app.example.com": {},
			"api.example.com": {},
		},
	}

	// Populate initial valid configs
	for i := 0; i < 5; i++ {
		c, err := generateAndStoreECHConfig(caddyCtx, "public.example.com")
		if err != nil {
			t.Fatalf("failed to generate ECH config: %v", err)
		}
		tlsApp.EncryptedClientHello.configs["public.example.com"] = append(
			tlsApp.EncryptedClientHello.configs["public.example.com"],
			c,
		)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutines running publishECHConfigs concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					_ = tlsApp.publishECHConfigs(zap.NewNop())
				}
			}
		}()
	}

	// Goroutines mutating/rotating ECH configs concurrently under lock
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					tlsApp.EncryptedClientHello.configsMu.Lock()
					cfgs := tlsApp.EncryptedClientHello.configs["public.example.com"]
					if len(cfgs) > 0 {
						if cfgs[0].meta.Publications == nil {
							cfgs[0].meta.Publications = make(publicationHistory)
						}
						cfgs[0].meta.Publications[fmt.Sprintf("mock_pub_%d", id)] = map[string]time.Time{
							"test": time.Now(),
						}
					}
					// Add or trim configs
					if len(cfgs) > 10 {
						tlsApp.EncryptedClientHello.configs["public.example.com"] = cfgs[:5]
					} else {
						newCfg, err := generateAndStoreECHConfig(caddyCtx, "public.example.com")
						if err == nil {
							tlsApp.EncryptedClientHello.configs["public.example.com"] = append(
								tlsApp.EncryptedClientHello.configs["public.example.com"],
								newCfg,
							)
						}
					}
					tlsApp.EncryptedClientHello.configsMu.Unlock()
					time.Sleep(2 * time.Millisecond)
				}
			}
		}(i)
	}

	// Run concurrency test for 100ms
	time.Sleep(100 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}
