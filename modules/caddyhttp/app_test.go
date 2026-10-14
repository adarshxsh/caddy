package caddyhttp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type trackingQUICListener struct {
	closeCalls int
	closedAt   []time.Time
}

func (t *trackingQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *trackingQUICListener) Close() error {
	t.closeCalls++
	t.closedAt = append(t.closedAt, time.Now())
	return nil
}

func (t *trackingQUICListener) Addr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func TestApp_StopH3Server_DefersSecondClose(t *testing.T) {
	ln := &trackingQUICListener{}
	h3srv := &http3.Server{}

	srv := &Server{
		Listen:        []string{":443"},
		h3server:      h3srv,
		quicListeners: []http3.QUICListener{ln},
	}

	app := &App{
		logger: zap.NewNop(),
		Servers: map[string]*Server{
			"srv1": srv,
		},
	}

	err := app.Stop()
	assert.NoError(t, err)

	assert.Equal(t, 2, ln.closeCalls, "expected Close to be called twice")
	assert.Len(t, ln.closedAt, 2)
}
