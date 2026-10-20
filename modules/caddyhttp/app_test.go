package caddyhttp

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type sequenceTrackingListener struct {
	mu         sync.Mutex
	addr       net.Addr
	events     *[]string
	closeCount int
}

func (s *sequenceTrackingListener) Accept(ctx context.Context) (*quic.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *sequenceTrackingListener) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	*s.events = append(*s.events, "listener_close")
	return nil
}

func (s *sequenceTrackingListener) Addr() net.Addr {
	if s.addr == nil {
		return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4433}
	}
	return s.addr
}

func (s *sequenceTrackingListener) getCloseCountAndEventsCount() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCount, len(*s.events)
}

func TestStopH3ServerSequence(t *testing.T) {
	events := []string{}

	ln := &sequenceTrackingListener{events: &events}
	srv := &Server{
		Listen:        []string{"127.0.0.1:4433"},
		h3server:      &http3.Server{},
		quicListeners: []http3.QUICListener{ln},
		logger:        zap.NewNop(),
	}

	app := &App{
		Servers: map[string]*Server{
			"test": srv,
		},
		logger: zap.NewNop(),
	}

	err := app.Stop()
	require.NoError(t, err)

	closeCount, eventsCount := ln.getCloseCountAndEventsCount()
	assert.Equal(t, 2, closeCount, "expected quicListener Close to be called twice")
	assert.Equal(t, 2, eventsCount, "expected two listener_close events")
}
