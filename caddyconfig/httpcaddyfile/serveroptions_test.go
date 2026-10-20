package httpcaddyfile

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEarlyDataCaddyfileServerOptions(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPolicy  string
		want0RTT    *bool
		expectError bool
	}{
		{
			name: "inline policy reject_unsafe",
			input: `{
				servers {
					early_data reject_unsafe
				}
			}
			example.com`,
			wantPolicy:  caddyhttp.EarlyDataPolicyRejectUnsafe,
			expectError: false,
		},
		{
			name: "inline policy allow_all",
			input: `{
				servers {
					early_data allow_all
				}
			}
			example.com`,
			wantPolicy:  caddyhttp.EarlyDataPolicyAllowAll,
			expectError: false,
		},
		{
			name: "inline policy disable_0rtt",
			input: `{
				servers {
					early_data disable_0rtt
				}
			}
			example.com`,
			wantPolicy:  caddyhttp.EarlyDataPolicyDisable0RTT,
			expectError: false,
		},
		{
			name: "block policy allow_all",
			input: `{
				servers {
					early_data {
						policy allow_all
					}
				}
			}
			example.com`,
			wantPolicy:  caddyhttp.EarlyDataPolicyAllowAll,
			expectError: false,
		},
		{
			name: "invalid policy",
			input: `{
				servers {
					early_data invalid_policy
				}
			}
			example.com`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := caddyfile.Adapter{
				ServerType: ServerType{},
			}

			out, _, err := adapter.Adapt([]byte(tt.input), nil)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]*caddyhttp.Server `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}

			err = json.Unmarshal(out, &config)
			require.NoError(t, err)

			srv, ok := config.Apps.HTTP.Servers["srv0"]
			require.True(t, ok, "srv0 should exist in servers map")
			require.NotNil(t, srv.EarlyData)
			assert.Equal(t, tt.wantPolicy, srv.EarlyData.Policy)

			if tt.wantPolicy == caddyhttp.EarlyDataPolicyDisable0RTT {
				require.NotNil(t, srv.Allow0RTT)
				assert.False(t, *srv.Allow0RTT)
			}
		})
	}
}
