package caddyhttp

import (
	"crypto/tls"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoggableTLSConnState_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name                 string
		state                tls.ConnectionState
		wantHandshakeComplete bool
		wantEarlyData        bool
		wantResumed          bool
	}{
		{
			name: "handshake complete, standard resumption",
			state: tls.ConnectionState{
				DidResume:         true,
				HandshakeComplete: true,
				Version:           tls.VersionTLS13,
			},
			wantHandshakeComplete: true,
			wantEarlyData:        false,
			wantResumed:          true,
		},
		{
			name: "handshake incomplete, early data accepted",
			state: tls.ConnectionState{
				DidResume:         true,
				HandshakeComplete: false,
				Version:           tls.VersionTLS13,
			},
			wantHandshakeComplete: false,
			wantEarlyData:        true,
			wantResumed:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			loggable := LoggableTLSConnState(tt.state)
			if err := loggable.MarshalLogObject(enc); err != nil {
				t.Fatalf("unexpected error marshaling log object: %v", err)
			}

			if got, ok := enc.Fields["handshake_complete"].(bool); !ok || got != tt.wantHandshakeComplete {
				t.Errorf("handshake_complete = %v (ok=%v), want %v", enc.Fields["handshake_complete"], ok, tt.wantHandshakeComplete)
			}

			if got, ok := enc.Fields["early_data"].(bool); !ok || got != tt.wantEarlyData {
				t.Errorf("early_data = %v (ok=%v), want %v", enc.Fields["early_data"], ok, tt.wantEarlyData)
			}

			if got, ok := enc.Fields["resumed"].(bool); !ok || got != tt.wantResumed {
				t.Errorf("resumed = %v (ok=%v), want %v", enc.Fields["resumed"], ok, tt.wantResumed)
			}
		})
	}
}
