package reverseproxy

import (
	"bytes"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// TestCaddyfileStreamKeepAlive verifies single duration and block syntax parsing for stream_keepalive.
func TestCaddyfileStreamKeepAlive(t *testing.T) {
	tests := []struct {
		name           string
		caddyfileInput string
		expectedProbe  time.Duration
		expectedPing   time.Duration
		expectErr      bool
	}{
		{
			name:           "single duration syntax",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive 30s\n}",
			expectedProbe:  30 * time.Second,
			expectedPing:   30 * time.Second,
			expectErr:      false,
		},
		{
			name:           "block syntax both probe and ping",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive {\n probe 20s\n ping 10s\n }\n}",
			expectedProbe:  20 * time.Second,
			expectedPing:   10 * time.Second,
			expectErr:      false,
		},
		{
			name:           "block syntax probe only",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive {\n probe 15s\n }\n}",
			expectedProbe:  15 * time.Second,
			expectedPing:   0,
			expectErr:      false,
		},
		{
			name:           "block syntax ping only",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive {\n ping 5s\n }\n}",
			expectedProbe:  0,
			expectedPing:   5 * time.Second,
			expectErr:      false,
		},
		{
			name:           "invalid subdirective in block",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive {\n unknown 5s\n }\n}",
			expectErr:      true,
		},
		{
			name:           "invalid duration string",
			caddyfileInput: "reverse_proxy localhost:8080 {\n stream_keepalive invalid_time\n}",
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.caddyfileInput)
			h := new(Handler)
			err := h.UnmarshalCaddyfile(d)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h.StreamKeepAlive == nil {
				t.Fatalf("expected StreamKeepAlive to be non-nil")
			}
			if time.Duration(h.StreamKeepAlive.ProbeInterval) != tt.expectedProbe {
				t.Errorf("ProbeInterval = %v, want %v", time.Duration(h.StreamKeepAlive.ProbeInterval), tt.expectedProbe)
			}
			if time.Duration(h.StreamKeepAlive.PingInterval) != tt.expectedPing {
				t.Errorf("PingInterval = %v, want %v", time.Duration(h.StreamKeepAlive.PingInterval), tt.expectedPing)
			}
		})
	}
}

// mockConnWrapper implements Unwrap() for testing socket unwrapping.
type mockConnWrapper struct {
	net.Conn
	unwrapped net.Conn
}

func (m *mockConnWrapper) Unwrap() net.Conn {
	return m.unwrapped
}

// mockTCPConn mocks keepalive setter methods.
type mockTCPConn struct {
	net.Conn
	keepAliveEnabled bool
	keepAlivePeriod  time.Duration
	configSet        bool
	config           net.KeepAliveConfig
}

func (m *mockTCPConn) SetKeepAlive(enable bool) error {
	m.keepAliveEnabled = enable
	return nil
}

func (m *mockTCPConn) SetKeepAlivePeriod(d time.Duration) error {
	m.keepAlivePeriod = d
	return nil
}

func (m *mockTCPConn) SetKeepAliveConfig(cfg net.KeepAliveConfig) error {
	m.configSet = true
	m.config = cfg
	return nil
}

// TestEnableTCPKeepAlive verifies socket unwrapping and keepalive setting.
func TestEnableTCPKeepAlive(t *testing.T) {
	// Test 1: Direct mock TCP Conn
	mConn := &mockTCPConn{}
	enableTCPKeepAlive(mConn, 10*time.Second)
	if !mConn.configSet && (!mConn.keepAliveEnabled || mConn.keepAlivePeriod != 10*time.Second) {
		t.Errorf("expected keepalive configured on direct mock TCP conn")
	}

	// Test 2: Wrapped Conn
	innerConn := &mockTCPConn{}
	wrappedConn := &mockConnWrapper{unwrapped: innerConn}
	enableTCPKeepAlive(wrappedConn, 15*time.Second)
	if !innerConn.configSet && (!innerConn.keepAliveEnabled || innerConn.keepAlivePeriod != 15*time.Second) {
		t.Errorf("expected keepalive configured on unwrapped inner conn")
	}

	// Test 3: Non-TCP socket should be safely ignored without panic
	dummyBuf := &bytes.Buffer{}
	enableTCPKeepAlive(dummyBuf, 10*time.Second)
}

// TestIdlePingWriter verifies ping frame generation on idle timeout.
func TestIdlePingWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	pingInterval := 30 * time.Millisecond

	// Test server-side ping (isClient = false -> unmasked 0x89 0x00)
	pwServer := newIdlePingWriter(buf, pingInterval, false)

	// Wait for idle timer to fire
	time.Sleep(70 * time.Millisecond)

	pwServer.Stop()

	res := buf.Bytes()
	if len(res) < 2 {
		t.Fatalf("expected at least 2 bytes for ping frame, got %d", len(res))
	}
	if res[0] != 0x89 || res[1] != 0x00 {
		t.Errorf("expected server ping frame 0x89 0x00, got 0x%x 0x%x", res[0], res[1])
	}

	// Test client-side ping (isClient = true -> masked 0x89 0x80 <4 byte mask key>)
	bufClient := &bytes.Buffer{}
	pwClient := newIdlePingWriter(bufClient, pingInterval, true)

	time.Sleep(70 * time.Millisecond)
	pwClient.Stop()

	resClient := bufClient.Bytes()
	if len(resClient) < 6 {
		t.Fatalf("expected at least 6 bytes for client ping frame, got %d", len(resClient))
	}
	if resClient[0] != 0x89 || resClient[1] != 0x80 {
		t.Errorf("expected client ping header 0x89 0x80, got 0x%x 0x%x", resClient[0], resClient[1])
	}
}

// TestIsWebsocket verifies detection of WebSocket upgrade requests.
func TestIsWebsocket(t *testing.T) {
	wsReq, _ := http.NewRequest("GET", "http://example.com", nil)
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("Upgrade", "websocket")

	if !isWebsocket(wsReq) {
		t.Errorf("expected isWebsocket to return true")
	}

	nonWsReq, _ := http.NewRequest("GET", "http://example.com", nil)
	nonWsReq.Header.Set("Connection", "Upgrade")
	nonWsReq.Header.Set("Upgrade", "h2c")

	if isWebsocket(nonWsReq) {
		t.Errorf("expected isWebsocket to return false for non-websocket upgrade")
	}
}
