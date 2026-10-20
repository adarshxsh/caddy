package caddyhttp

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type dummyHandler struct {
	executed   bool
	earlyData  string
	statusCode int
}

func (h *dummyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.executed = true
	h.earlyData = r.Header.Get("Early-Data")
	status := h.statusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	return nil
}

func TestEarlyData_DefaultRejectUnsafe(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		isEarlyData   bool
		clientHeader  string
		wantStatus    int
		wantExecuted  bool
		wantHeaderVal string
	}{
		{
			name:          "0-RTT GET is safe and passes",
			method:        http.MethodGet,
			isEarlyData:   true,
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "1",
		},
		{
			name:          "0-RTT HEAD is safe and passes",
			method:        http.MethodHead,
			isEarlyData:   true,
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "1",
		},
		{
			name:          "0-RTT OPTIONS is safe and passes",
			method:        http.MethodOptions,
			isEarlyData:   true,
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "1",
		},
		{
			name:          "0-RTT TRACE is safe and passes",
			method:        http.MethodTrace,
			isEarlyData:   true,
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "1",
		},
		{
			name:         "0-RTT POST is unsafe and rejected with 425",
			method:       http.MethodPost,
			isEarlyData:  true,
			wantStatus:   http.StatusTooEarly,
			wantExecuted: false,
		},
		{
			name:         "0-RTT PUT is unsafe and rejected with 425",
			method:       http.MethodPut,
			isEarlyData:  true,
			wantStatus:   http.StatusTooEarly,
			wantExecuted: false,
		},
		{
			name:         "0-RTT DELETE is unsafe and rejected with 425",
			method:       http.MethodDelete,
			isEarlyData:  true,
			wantStatus:   http.StatusTooEarly,
			wantExecuted: false,
		},
		{
			name:         "0-RTT PATCH is unsafe and rejected with 425",
			method:       http.MethodPatch,
			isEarlyData:  true,
			wantStatus:   http.StatusTooEarly,
			wantExecuted: false,
		},
		{
			name:         "0-RTT CONNECT is unsafe and rejected with 425",
			method:       http.MethodConnect,
			isEarlyData:  true,
			wantStatus:   http.StatusTooEarly,
			wantExecuted: false,
		},
		{
			name:          "1-RTT POST passes and strips spoofed Early-Data header",
			method:        http.MethodPost,
			isEarlyData:   false,
			clientHeader:  "1",
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "",
		},
		{
			name:          "1-RTT GET passes and strips client Early-Data header",
			method:        http.MethodGet,
			isEarlyData:   false,
			clientHeader:  "something",
			wantStatus:    http.StatusOK,
			wantExecuted:  true,
			wantHeaderVal: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &dummyHandler{}
			srv := &Server{
				primaryHandlerChain: handler,
				logger:              zap.NewNop(),
				errorLogger:         zap.NewNop(),
				accessLogger:        zap.NewNop(),
			}

			req := httptest.NewRequest(tt.method, "/", nil)
			if tt.clientHeader != "" {
				req.Header.Set("Early-Data", tt.clientHeader)
			}

			if tt.isEarlyData {
				req.TLS = &tls.ConnectionState{
					HandshakeComplete: false,
				}
			} else {
				req.TLS = &tls.ConnectionState{
					HandshakeComplete: true,
				}
			}

			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, tt.wantExecuted, handler.executed)
			if tt.wantExecuted {
				assert.Equal(t, tt.wantHeaderVal, handler.earlyData)
			}
		})
	}
}

func TestEarlyData_AllowAllPolicy(t *testing.T) {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	}

	for _, m := range methods {
		t.Run("0-RTT "+m+" with allow_all", func(t *testing.T) {
			handler := &dummyHandler{}
			srv := &Server{
				EarlyData: &EarlyDataConfig{
					Policy: EarlyDataPolicyAllowAll,
				},
				primaryHandlerChain: handler,
				logger:              zap.NewNop(),
				errorLogger:         zap.NewNop(),
				accessLogger:        zap.NewNop(),
			}

			req := httptest.NewRequest(m, "/", nil)
			req.TLS = &tls.ConnectionState{
				HandshakeComplete: false,
			}

			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.True(t, handler.executed)
			assert.Equal(t, "1", handler.earlyData)
		})
	}
}

func TestEarlyData_Disable0RTTPolicy(t *testing.T) {
	methods := []string{
		http.MethodGet, http.MethodPost,
	}

	for _, m := range methods {
		t.Run("0-RTT "+m+" with disable_0rtt", func(t *testing.T) {
			handler := &dummyHandler{}
			srv := &Server{
				EarlyData: &EarlyDataConfig{
					Policy: EarlyDataPolicyDisable0RTT,
				},
				primaryHandlerChain: handler,
				logger:              zap.NewNop(),
				errorLogger:         zap.NewNop(),
				accessLogger:        zap.NewNop(),
			}

			req := httptest.NewRequest(m, "/", nil)
			req.TLS = &tls.ConnectionState{
				HandshakeComplete: false,
			}

			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusTooEarly, rec.Code)
			assert.False(t, handler.executed)
		})
	}
}

func TestEarlyData_AppValidation(t *testing.T) {
	app := &App{
		Servers: map[string]*Server{
			"srv1": {
				EarlyData: &EarlyDataConfig{Policy: EarlyDataPolicyRejectUnsafe},
			},
			"srv2": {
				EarlyData: &EarlyDataConfig{Policy: EarlyDataPolicyAllowAll},
			},
			"srv3": {
				EarlyData: &EarlyDataConfig{Policy: EarlyDataPolicyDisable0RTT},
			},
		},
	}
	err := app.Validate()
	require.NoError(t, err)

	invalidApp := &App{
		Servers: map[string]*Server{
			"srv_bad": {
				EarlyData: &EarlyDataConfig{Policy: "invalid_policy"},
			},
		},
	}
	err = invalidApp.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid early_data policy 'invalid_policy'")
}

type errHandler struct{}

func (errHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return errors.New("handler error")
}
