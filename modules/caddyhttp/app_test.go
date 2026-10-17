package caddyhttp

import (
	"context"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type trackingQUICListener struct {
	closeCalls          int
	shutdownCalledBeforeClose bool
	h3server            *http3.Server
}

func (t *trackingQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *trackingQUICListener) Addr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}

func (t *trackingQUICListener) Close() error {
	t.closeCalls++
	return nil
}

func TestStopH3ServerSequence(t *testing.T) {
	logger := zap.NewNop()
	app := &App{
		logger: logger,
	}

	listener := &trackingQUICListener{}
	h3srv := &http3.Server{}

	server := &Server{
		h3server:      h3srv,
		quicListeners: []http3.QUICListener{listener},
	}

	app.Servers = map[string]*Server{
		"srv0": server,
	}

	err := app.Stop()
	assert.NoError(t, err)
	assert.Equal(t, 2, listener.closeCalls)
}
