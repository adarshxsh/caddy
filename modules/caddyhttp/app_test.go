package caddyhttp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type mockFakeCloseQuicListener struct {
	closed        int
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelCauseFunc
	shutdownState []string
}

func (m *mockFakeCloseQuicListener) Accept(ctx context.Context) (*quic.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *mockFakeCloseQuicListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed == 0 {
		m.closed = 1
		m.cancel(fmt.Errorf("fake closed"))
		m.shutdownState = append(m.shutdownState, "first_close_context_canceled")
	} else if m.closed == 1 {
		m.closed = 2
		m.shutdownState = append(m.shutdownState, "second_close_pool_deleted")
	}
	return nil
}

func (m *mockFakeCloseQuicListener) Addr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func TestStopH3ServerShutdownSequence(t *testing.T) {
	lnCtx, cancel := context.WithCancelCause(context.Background())

	ln := &mockFakeCloseQuicListener{
		ctx:    lnCtx,
		cancel: cancel,
	}

	h3srv := &http3.Server{}

	srv := &Server{
		Listen:        []string{"127.0.0.1:12345"},
		h3server:      h3srv,
		quicListeners: []http3.QUICListener{ln},
	}

	app := &App{
		logger:  zap.NewNop(),
		Servers: map[string]*Server{"test": srv},
	}

	// Before stopping, listener context must be active
	assert.NoError(t, ln.ctx.Err())

	err := app.Stop()
	assert.NoError(t, err)

	// After stop completes, listener context should now be canceled (from post-shutdown Close())
	assert.Error(t, ln.ctx.Err())

	ln.mu.Lock()
	defer ln.mu.Unlock()

	// Verify both close stages executed in order after Shutdown
	assert.Equal(t, []string{"first_close_context_canceled", "second_close_pool_deleted"}, ln.shutdownState)
}
