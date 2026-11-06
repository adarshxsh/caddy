package caddytls

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestPublicationHistoryClone(t *testing.T) {
	t.Run("nil publicationHistory", func(t *testing.T) {
		var ph publicationHistory
		if ph.Clone() != nil {
			t.Fatal("expected nil clone for nil publicationHistory")
		}
	})

	t.Run("empty publicationHistory", func(t *testing.T) {
		ph := make(publicationHistory)
		cloned := ph.Clone()
		if cloned == nil {
			t.Fatal("expected non-nil clone for empty publicationHistory")
		}
		if len(cloned) != 0 {
			t.Fatalf("expected empty clone, got len %d", len(cloned))
		}
	})

	t.Run("populated publicationHistory with inner map isolation", func(t *testing.T) {
		now := time.Now()
		ph := publicationHistory{
			"pub1": map[string]time.Time{
				"example.com": now,
			},
			"pub2": nil,
		}

		cloned := ph.Clone()

		// Mutate clone
		cloned["pub1"]["example.com"] = now.Add(time.Hour)
		cloned["pub1"]["new.com"] = now
		cloned["pub3"] = map[string]time.Time{"other.com": now}

		// Verify original remains untouched
		if ph["pub1"]["example.com"].Equal(now.Add(time.Hour)) {
			t.Fatal("original map value was mutated when clone was updated")
		}
		if _, ok := ph["pub1"]["new.com"]; ok {
			t.Fatal("original map gained new inner key when clone was updated")
		}
		if _, ok := ph["pub3"]; ok {
			t.Fatal("original map gained new publisher key when clone was updated")
		}
		if ph["pub2"] != nil {
			t.Fatal("nil inner map should remain nil in clone")
		}
	})
}

func TestECHConfigClone(t *testing.T) {
	now := time.Now()
	cfg := echConfig{
		ConfigID:      42,
		RawPublicName: "public.example.com",
		meta: echConfigMeta{
			Created: now,
			Publications: publicationHistory{
				"dns": map[string]time.Time{
					"inner.example.com": now,
				},
			},
		},
	}

	cloned := cfg.Clone()
	if cloned.ConfigID != cfg.ConfigID || cloned.RawPublicName != cfg.RawPublicName {
		t.Fatalf("struct scalar fields not copied correctly: got ID %d, name %s", cloned.ConfigID, cloned.RawPublicName)
	}

	// Mutate clone's publications
	cloned.meta.Publications["dns"]["inner.example.com"] = now.Add(2 * time.Hour)
	cloned.meta.Publications["dns"]["another.com"] = now

	// Verify original is isolated
	if cfg.meta.Publications["dns"]["inner.example.com"].Equal(now.Add(2 * time.Hour)) {
		t.Fatal("original echConfig meta.Publications was mutated when clone was updated")
	}
	if _, ok := cfg.meta.Publications["dns"]["another.com"]; ok {
		t.Fatal("original echConfig meta.Publications gained key when clone was updated")
	}
}

type testECHPublisher struct {
	key string
}

func (p testECHPublisher) PublisherKey() string {
	return p.key
}

func (p testECHPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	return nil
}

func TestECHConcurrentPublicationAndRotation(t *testing.T) {
	tmpStorage := &certmagic.FileStorage{Path: t.TempDir()}
	oldStorage := certmagic.Default.Storage
	certmagic.Default.Storage = tmpStorage
	defer func() { certmagic.Default.Storage = oldStorage }()

	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed to provision caddy context: %v", err)
	}

	cfg1, err := generateAndStoreECHConfig(caddyCtx, "public.example.com")
	if err != nil {
		t.Fatalf("failed to generate ECH config: %v", err)
	}
	cfg1.meta.Publications = publicationHistory{
		"pub1": map[string]time.Time{
			"site1.example.com": time.Now(),
		},
	}

	cfg2, err := generateAndStoreECHConfig(caddyCtx, "public.example.com")
	if err != nil {
		t.Fatalf("failed to generate ECH config 2: %v", err)
	}

	tlsApp := &TLS{
		ctx: caddyCtx,
		serverNames: map[string]serverNameRegistration{
			"site1.example.com": {},
			"site2.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
		EncryptedClientHello: &ECH{
			Publication: []*ECHPublication{
				{
					publishers: []ECHPublisher{testECHPublisher{key: "pub1"}},
				},
			},
			configsMu: new(sync.RWMutex),
			configs: map[string][]echConfig{
				"public.example.com": {cfg1},
			},
		},
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	// Worker 1: Repeated publication tasks
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = tlsApp.publishECHConfigs(logger)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 2: Concurrent publication tasks with different inner names
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = tlsApp.publishECHConfigs(logger)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 3: Concurrent reader cloning configs (simulating TLS handshakes or GET keys)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			tlsApp.EncryptedClientHello.configsMu.RLock()
			for _, list := range tlsApp.EncryptedClientHello.configs {
				for _, c := range list {
					_ = c.Clone()
				}
			}
			tlsApp.EncryptedClientHello.configsMu.RUnlock()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 4: Concurrent writer simulating key rotation / updating configs list
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			tlsApp.EncryptedClientHello.configsMu.Lock()
			tlsApp.EncryptedClientHello.configs["public.example.com"] = []echConfig{cfg1, cfg2}
			tlsApp.EncryptedClientHello.configsMu.Unlock()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	wg.Wait()
}
