package caddytls

import (
	"sync"
	"testing"
	"time"
)

func TestTLSStopRepeated(t *testing.T) {
	tlsApp := &TLS{
		storageCleanStop:   make(chan struct{}),
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	for i := 0; i < 3; i++ {
		err := tlsApp.Stop()
		if err != nil {
			t.Fatalf("unexpected error on Stop() call %d: %v", i+1, err)
		}
	}
}

func TestTLSStopConcurrent(t *testing.T) {
	tlsApp := &TLS{
		storageCleanStop:   make(chan struct{}),
		storageCleanTicker: time.NewTicker(time.Hour),
	}

	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := tlsApp.Stop()
			if err != nil {
				t.Errorf("unexpected error on concurrent Stop(): %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestTLSStopNil(t *testing.T) {
	tlsApp := &TLS{}

	err := tlsApp.Stop()
	if err != nil {
		t.Fatalf("unexpected error on Stop() with nil fields: %v", err)
	}
}
