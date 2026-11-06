package caddytls

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

type mockECHPublisher struct {
	key string
}

func (m *mockECHPublisher) PublisherKey() string {
	return m.key
}

func (m *mockECHPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, configList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestECHClone(t *testing.T) {
	t.Run("publicationHistory", func(t *testing.T) {
		var nilHistory publicationHistory
		if cloned := nilHistory.Clone(); cloned != nil {
			t.Fatalf("expected nil clone for nil history, got %v", cloned)
		}

		emptyHistory := make(publicationHistory)
		if cloned := emptyHistory.Clone(); cloned != nil {
			t.Fatalf("expected nil clone for empty history, got %v", cloned)
		}

		origTime := time.Now()
		orig := publicationHistory{
			"pub1": {
				"example.com": origTime,
			},
			"empty_pub": map[string]time.Time{},
		}

		cloned := orig.Clone()

		// Verify deep copy
		cloned["pub1"]["example.com"] = origTime.Add(1 * time.Hour)
		if orig["pub1"]["example.com"].Equal(cloned["pub1"]["example.com"]) {
			t.Fatalf("modifying cloned map mutated original map")
		}

		cloned["new_pub"] = map[string]time.Time{"new.com": origTime}
		if _, ok := orig["new_pub"]; ok {
			t.Fatalf("adding entry to cloned map affected original map")
		}
	})

	t.Run("echConfig", func(t *testing.T) {
		orig := echConfig{
			Version:       draftTLSESNI25,
			ConfigID:      1,
			RawPublicName: "public.example.com",
			CipherSuites: []hpkeSymmetricCipherSuite{
				{KDFID: 1, AEADID: 1},
			},
			configBin:  []byte{1, 2, 3},
			privKeyBin: []byte{4, 5, 6},
			meta: echConfigMeta{
				Created: time.Now(),
				Publications: publicationHistory{
					"pub1": {"domain.com": time.Now()},
				},
			},
		}

		cloned := orig.Clone()

		cloned.CipherSuites[0].KDFID = 99
		if orig.CipherSuites[0].KDFID == 99 {
			t.Fatalf("modifying cloned cipher suites mutated original")
		}

		cloned.configBin[0] = 0xFF
		if orig.configBin[0] == 0xFF {
			t.Fatalf("modifying cloned configBin mutated original")
		}

		cloned.meta.Publications["pub1"]["domain.com"] = time.Now().Add(10 * time.Hour)
		if orig.meta.Publications["pub1"]["domain.com"].Equal(cloned.meta.Publications["pub1"]["domain.com"]) {
			t.Fatalf("modifying cloned meta publications mutated original")
		}
	})
}

func TestECHConcurrentPublishAndRotate(t *testing.T) {
	var cfg caddy.Config
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatalf("ProvisionContext failed: %v", err)
	}

	logger := zap.NewNop()

	ech := &ECH{
		Configs: []ECHConfiguration{
			{PublicName: "public.example.com"},
		},
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{
					&mockECHPublisher{key: "mock_pub_1"},
					&mockECHPublisher{key: "mock_pub_2"},
				},
			},
		},
	}

	tlsApp := &TLS{
		ctx:                  ctx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"app1.example.com": {},
			"app2.example.com": {},
		},
		serverNamesMu: new(sync.Mutex),
	}

	outerNames, err := ech.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if len(outerNames) == 0 {
		t.Fatalf("expected outer names, got 0")
	}

	var wg sync.WaitGroup
	const numRoutines = 10

	// Goroutines running publishECHConfigs
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
	}

	// Goroutines running rotateECHKeys
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				ech.configsMu.Lock()
				_ = ech.rotateECHKeys(ctx, logger, true)
				ech.configsMu.Unlock()
			}
		}()
	}

	// Goroutines reading configs
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				ech.configsMu.RLock()
				_ = len(ech.stdlibReady)
				_ = len(ech.configs["public.example.com"])
				ech.configsMu.RUnlock()
			}
		}()
	}

	wg.Wait()
}
