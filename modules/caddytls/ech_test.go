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

type testPublisher struct {
	key string
}

func (p *testPublisher) PublisherKey() string {
	return p.key
}

func (p *testPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	time.Sleep(1 * time.Millisecond)
	return nil
}

func TestConcurrentECHPublication(t *testing.T) {
	tempDir := t.TempDir()
	certmagic.Default.Storage = &certmagic.FileStorage{Path: tempDir}

	caddyCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("failed provisioning context: %v", err)
	}

	publicName := "public.example.com"
	echCfg, err := generateAndStoreECHConfig(caddyCtx, publicName)
	if err != nil {
		t.Fatalf("failed generating initial ECH config: %v", err)
	}

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			publicName: {echCfg},
		},
		Publication: []*ECHPublication{
			{
				publishers: []ECHPublisher{
					&testPublisher{key: "pub1"},
					&testPublisher{key: "pub2"},
				},
			},
		},
	}

	tlsApp := &TLS{
		ctx:                  caddyCtx,
		EncryptedClientHello: ech,
		serverNames: map[string]serverNameRegistration{
			"app1.example.com": {},
			"app2.example.com": {},
		},
	}

	logger := zap.NewNop()
	var wg sync.WaitGroup

	// Concurrent publishers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = tlsApp.publishECHConfigs(logger)
			}
		}()
	}

	// Concurrent rotators
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				ech.configsMu.Lock()
				_ = ech.rotateECHKeys(caddyCtx, logger, false)
				ech.configsMu.Unlock()
			}
		}()
	}

	wg.Wait()
}
