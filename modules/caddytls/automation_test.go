package caddytls

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAutomationPolicyMakeCertMagicConfigImplicitTailscaleManagersOnly(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
		subjects: []string{"test-node.example.ts.net"},
	}

	cfg, err := ap.makeCertMagicConfig(&TLS{
		logger: zap.NewNop(),
	}, nil, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("making certmagic config: %v", err)
	}
	if cfg.OnDemand == nil {
		t.Fatal("expected on-demand config to be set")
	}
	if len(cfg.Issuers) != 0 {
		t.Fatalf("expected no issuers for tailscale-managed ts.net policy, got %d", len(cfg.Issuers))
	}
}

func TestAutomationPolicyImplicitTailscaleManagersOnlyCatchAll(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
	}
	if ap.implicitTailscaleManagersOnly() {
		t.Fatal("expected catch-all manager policy to remain outside tailscale-only special case")
	}
}

func TestTLSStopIdempotent(t *testing.T) {
	tls := &TLS{
		logger: zap.NewNop(),
		ctx:    caddy.Context{},
	}
	tls.keepStorageClean()
	if err := tls.Stop(); err != nil {
		t.Fatalf("first Stop() failed: %v", err)
	}
	if err := tls.Stop(); err != nil {
		t.Fatalf("second Stop() failed: %v", err)
	}
}
