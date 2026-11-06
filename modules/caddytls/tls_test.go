package caddytls

import (
	"testing"

	"go.uber.org/zap"
)

func TestTLSStopIdempotent(t *testing.T) {
	tlsApp := &TLS{
		logger: zap.NewNop(),
	}

	tlsApp.keepStorageClean()

	if tlsApp.storageCleanTicker == nil {
		t.Fatal("expected storageCleanTicker to be initialized")
	}

	// First Stop call
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsApp.storageCleanTicker != nil {
		t.Error("expected storageCleanTicker to be nil after Stop")
	}

	// Second Stop call should not panic and should succeed
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on second Stop: %v", err)
	}

	// Stop on an unstarted TLS instance should also succeed
	emptyTLS := &TLS{}
	if err := emptyTLS.Stop(); err != nil {
		t.Fatalf("unexpected error when stopping unstarted TLS: %v", err)
	}
}
