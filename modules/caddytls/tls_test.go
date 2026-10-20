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

	if tlsApp.storageCleanStop == nil {
		t.Fatal("expected storageCleanStop channel to be initialized")
	}
	if tlsApp.storageCleanTicker == nil {
		t.Fatal("expected storageCleanTicker to be initialized")
	}

	// First Stop call
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on first Stop: %v", err)
	}

	if tlsApp.storageCleanStop != nil {
		t.Error("expected storageCleanStop to be nil after Stop")
	}
	if tlsApp.storageCleanTicker != nil {
		t.Error("expected storageCleanTicker to be nil after Stop")
	}

	// Second Stop call should not panic and should succeed
	if err := tlsApp.Stop(); err != nil {
		t.Fatalf("unexpected error on second Stop: %v", err)
	}

	// Also test when storageCleanStop is non-nil but already closed
	ch := make(chan struct{})
	close(ch)
	tlsAppClosedCh := &TLS{
		storageCleanStop: ch,
	}
	if err := tlsAppClosedCh.Stop(); err != nil {
		t.Fatalf("unexpected error when stopping with closed channel: %v", err)
	}
	if tlsAppClosedCh.storageCleanStop != nil {
		t.Error("expected storageCleanStop to be nil after Stop")
	}
}
