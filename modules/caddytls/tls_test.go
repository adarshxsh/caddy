package caddytls

import (
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestTLSStopIdempotent(t *testing.T) {
	ctx, _ := caddy.ProvisionContext(&caddy.Config{})
	logger := zap.NewNop()

	t.Run("sequential stop", func(t *testing.T) {
		tlsApp := &TLS{ctx: ctx, logger: logger}
		tlsApp.keepStorageClean()

		// Call Stop multiple times sequentially
		for i := 0; i < 5; i++ {
			if err := tlsApp.Stop(); err != nil {
				t.Fatalf("unexpected error on Stop() call %d: %v", i, err)
			}
		}

		if tlsApp.storageCleanStop != nil {
			t.Errorf("expected storageCleanStop to be nil after Stop(), got %v", tlsApp.storageCleanStop)
		}
		if tlsApp.storageCleanTicker != nil {
			t.Errorf("expected storageCleanTicker to be nil after Stop(), got %v", tlsApp.storageCleanTicker)
		}
	})

	t.Run("concurrent stop", func(t *testing.T) {
		tlsApp := &TLS{ctx: ctx, logger: logger}
		tlsApp.keepStorageClean()

		var wg sync.WaitGroup
		const numGoroutines = 10
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := tlsApp.Stop(); err != nil {
					t.Errorf("unexpected error on concurrent Stop(): %v", err)
				}
			}()
		}
		wg.Wait()

		if tlsApp.storageCleanStop != nil {
			t.Errorf("expected storageCleanStop to be nil after concurrent Stop(), got %v", tlsApp.storageCleanStop)
		}
		if tlsApp.storageCleanTicker != nil {
			t.Errorf("expected storageCleanTicker to be nil after concurrent Stop(), got %v", tlsApp.storageCleanTicker)
		}
	})

	t.Run("unstarted stop", func(t *testing.T) {
		tlsApp := &TLS{ctx: ctx, logger: logger}
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error stopping unstarted TLS: %v", err)
		}
		if err := tlsApp.Stop(); err != nil {
			t.Fatalf("unexpected error on repeated stop of unstarted TLS: %v", err)
		}
	})
}
