package caddyhttp

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoggableTLSConnState_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name         string
		info         *EarlyDataInfo
		wantAccepted bool
		wantRejected bool
	}{
		{
			name:         "0-RTT accepted",
			info:         &EarlyDataInfo{Used0RTT: true, Status: "accepted"},
			wantAccepted: true,
			wantRejected: false,
		},
		{
			name:         "0-RTT rejected fallback 1RTT",
			info:         &EarlyDataInfo{Used0RTT: false, Status: "rejected_fallback_1rtt"},
			wantAccepted: false,
			wantRejected: true,
		},
		{
			name:         "No 0-RTT",
			info:         &EarlyDataInfo{Used0RTT: false, Status: "none"},
			wantAccepted: false,
			wantRejected: false,
		},
		{
			name:         "Nil early data info",
			info:         nil,
			wantAccepted: false,
			wantRejected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.info != nil {
				ctx = context.WithValue(ctx, EarlyDataCtxKey, *tt.info)
			}

			loggable := LoggableTLSConnState{
				ConnectionState: tls.ConnectionState{
					Version:   tls.VersionTLS13,
					DidResume: true,
				},
				Ctx: ctx,
			}

			enc := zapcore.NewMapObjectEncoder()
			if err := loggable.MarshalLogObject(enc); err != nil {
				t.Fatalf("unexpected error marshaling log object: %v", err)
			}

			accepted, ok := enc.Fields["early_data_accepted"].(bool)
			if !ok || accepted != tt.wantAccepted {
				t.Errorf("early_data_accepted = %v (ok=%v), want %v", accepted, ok, tt.wantAccepted)
			}

			rejected, ok := enc.Fields["early_data_rejected"].(bool)
			if !ok || rejected != tt.wantRejected {
				t.Errorf("early_data_rejected = %v (ok=%v), want %v", rejected, ok, tt.wantRejected)
			}
		})
	}
}

func TestLoggableHTTPRequest_MarshalLogObject_TLS(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{
		Version:   tls.VersionTLS13,
		DidResume: true,
	}
	ctx := context.WithValue(req.Context(), EarlyDataCtxKey, EarlyDataInfo{
		Used0RTT: true,
		Status:   "accepted",
	})
	req = req.WithContext(ctx)

	loggable := LoggableHTTPRequest{Request: req}
	enc := zapcore.NewMapObjectEncoder()
	if err := loggable.MarshalLogObject(enc); err != nil {
		t.Fatalf("unexpected error marshaling log object: %v", err)
	}

	tlsObj, ok := enc.Fields["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls object field in encoded request, got %v", enc.Fields["tls"])
	}

	if accepted, _ := tlsObj["early_data_accepted"].(bool); !accepted {
		t.Errorf("expected tls.early_data_accepted to be true, got %v", tlsObj["early_data_accepted"])
	}
	if rejected, _ := tlsObj["early_data_rejected"].(bool); rejected {
		t.Errorf("expected tls.early_data_rejected to be false, got %v", tlsObj["early_data_rejected"])
	}
}
