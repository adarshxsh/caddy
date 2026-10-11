package caddytls

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestPublicationHistoryClone(t *testing.T) {
	orig := publicationHistory{
		"pub1": {
			"example.com": time.Now(),
		},
	}
	cloned := orig.clone()

	// Mutate cloned map
	cloned["pub1"]["example.com"] = time.Now().Add(1 * time.Hour)
	cloned["pub2"] = map[string]time.Time{"other.com": time.Now()}

	if _, ok := orig["pub2"]; ok {
		t.Fatalf("original publicationHistory was mutated when cloned map was modified")
	}
	if orig["pub1"]["example.com"].Equal(cloned["pub1"]["example.com"]) {
		t.Fatalf("original timestamp was mutated when cloned timestamp was modified")
	}

	var nilPub publicationHistory
	if nilPub.clone() != nil {
		t.Fatalf("cloning nil publicationHistory should return nil")
	}
}

func TestECHConfigClone(t *testing.T) {
	orig := echConfig{
		ConfigID:      1,
		RawPublicName: "example.com",
		meta: echConfigMeta{
			Created: time.Now(),
			Publications: publicationHistory{
				"pub1": {"example.com": time.Now()},
			},
		},
	}
	cloned := orig.clone()

	cloned.meta.Publications["pub1"]["example.com"] = time.Now().Add(2 * time.Hour)
	cloned.meta.Publications["pub2"] = map[string]time.Time{"test.com": time.Now()}

	if _, ok := orig.meta.Publications["pub2"]; ok {
		t.Fatalf("original echConfig meta.Publications was mutated")
	}
	if orig.meta.Publications["pub1"]["example.com"].Equal(cloned.meta.Publications["pub1"]["example.com"]) {
		t.Fatalf("original echConfig timestamp was mutated")
	}
}

type dummyPublisher struct {
	key string
}

func (d dummyPublisher) PublisherKey() string {
	return d.key
}

func (d dummyPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestECHPublicationConcurrency(t *testing.T) {
	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("caddy.ProvisionContext failed: %v", err)
	}

	logger := zap.NewNop()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
		Publication: []*ECHPublication{
			{
				Domains:    []string{"inner1.example.com", "inner2.example.com"},
				publishers: []ECHPublisher{dummyPublisher{key: "dummy"}},
			},
		},
	}

	_, err = ech.Provision(ctx)
	if err != nil {
		t.Fatalf("ECH Provision failed: %v", err)
	}

	tlsApp := &TLS{
		ctx:                  ctx,
		EncryptedClientHello: ech,
		serverNames:          map[string]serverNameRegistration{"inner1.example.com": {}, "inner2.example.com": {}},
		serverNamesMu:        new(sync.Mutex),
	}

	var wg sync.WaitGroup
	const numGoroutines = 10
	const iterations = 20

	// Concurrent publishECHConfigs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
	}

	// Concurrent rotateECHKeys
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				ech.configsMu.Lock()
				_ = ech.rotateECHKeys(ctx, logger, false)
				ech.configsMu.Unlock()
			}
		}()
	}

	wg.Wait()
}
