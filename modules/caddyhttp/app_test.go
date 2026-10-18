package caddyhttp

import (
	"sync"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type trackingQUICListener struct {
	http3.QUICListener
	mu         sync.Mutex
	closeCount int
}

func (t *trackingQUICListener) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeCount++
	return nil
}

func TestHTTP3ShutdownSequenceOrder(t *testing.T) {
	h3srv := &http3.Server{}
	ln := &trackingQUICListener{}

	srv := &Server{
		h3server:      h3srv,
		quicListeners: []http3.QUICListener{ln},
	}

	app := &App{
		logger: zap.NewNop(),
		Servers: map[string]*Server{
			"srv0": srv,
		},
	}

	err := app.Stop()
	require.NoError(t, err)

	ln.mu.Lock()
	defer ln.mu.Unlock()

	// Verify that Caddy called Close twice on quicListeners during shutdown
	assert.Equal(t, 2, ln.closeCount)
}
