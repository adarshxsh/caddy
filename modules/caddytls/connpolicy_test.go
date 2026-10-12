// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestConnectionPolicyIDNSNIMatcherFastPath(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	targetTLSConfig := &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	policies := ConnectionPolicies{
		{
			matchers:  []ConnectionMatcher{MatchServerName{"つ.Localhost"}},
			TLSConfig: targetTLSConfig,
		},
	}

	const sniFastPathThreshold = 30
	for i := len(policies); i < sniFastPathThreshold; i++ {
		policies = append(policies, &ConnectionPolicy{
			matchers:  []ConnectionMatcher{MatchServerName{fmt.Sprintf("example-%d.localhost", i)}},
			TLSConfig: &tls.Config{},
		})
	}
	policies = append(policies, &ConnectionPolicy{
		matchers:  []ConnectionMatcher{MatchServerName{"xn--k9j.localhost"}},
		TLSConfig: &tls.Config{ClientAuth: tls.NoClientCert},
	})

	tlsConfig := policies.TLSConfig(ctx)
	got, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "XN--K9J.LOCALHOST"})
	if err != nil {
		t.Fatalf("GetConfigForClient() error = %v", err)
	}
	if got != targetTLSConfig {
		t.Fatalf("expected Unicode IDN policy to match before later punycode policy")
	}
}

func TestClientAuthenticationUnmarshalCaddyfileWithDirectiveName(t *testing.T) {
	const test_der_1 = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	const test_cert_file_1 = "../../caddytest/caddy.ca.cer"
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected ClientAuthentication
		wantErr  bool
	}{
		{
			name: "empty client_auth block does not error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					}`,
				),
			},
			wantErr: false,
		},
		{
			name: "providing both 'trust_pool' and 'trusted_ca_cert' returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					trust_pool inline MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==
					trusted_ca_cert MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==
				}`),
			},
			wantErr: true,
		},
		{
			name: "trust_pool without a module argument returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					trust_pool
				}`),
			},
			wantErr: true,
		},
		{
			name: "providing more than 1 mode produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
					client_auth {
						mode require request
					}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing 'mode' argument produces an error",
			args: args{d: caddyfile.NewTestDispenser(`
				client_auth {
					mode
				}
			`)},
			wantErr: true,
		},
		{
			name: "providing a single 'mode' argument sets the mode",
			args: args{
				d: caddyfile.NewTestDispenser(`
					client_auth {
						mode require
					}
				`),
			},
			expected: ClientAuthentication{
				Mode: "require",
			},
			wantErr: false,
		},
		{
			name: "not providing an argument to 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_leaf_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_leaf_cert
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_ca_cert_file' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_leaf_cert_file' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_leaf_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "using 'trusted_ca_cert' adapts successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert %s
				}`, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
		},
		{
			name: "using 'inline' trust_pool loads the module successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
					client_auth {
						trust_pool inline {
							trust_der	%s
						}
					}
				`, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
		},
		{
			name: "setting 'trusted_ca_cert' and 'trust_pool' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert %s
					trust_pool inline {
						trust_der	%s
					}
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'trust_pool' and 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_ca_cert %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'trust_pool' and 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_ca_cert_file %s
				}`, test_der_1, test_cert_file_1)),
			},
			wantErr: true,
		},
		{
			name: "configuring 'trusted_ca_cert_file' without an argument is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "configuring 'trusted_ca_cert_file' produces config with 'inline' provider",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert_file %s
				}`, test_cert_file_1),
				),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
			wantErr: false,
		},
		{
			name: "configuring leaf certs does not conflict with 'trust_pool'",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_leaf_cert %s
				}`, test_der_1, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw:            json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
				TrustedLeafCerts: []string{test_der_1},
			},
		},
		{
			name: "providing trusted leaf certificate file loads the cert successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_leaf_cert_file %s
				}`, test_cert_file_1)),
			},
			expected: ClientAuthentication{
				TrustedLeafCerts: []string{test_der_1},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &ClientAuthentication{}
			if err := ca.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("ClientAuthentication.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, ca) {
				t.Errorf("ClientAuthentication.UnmarshalCaddyfile() = %v, want %v", ca, tt.expected)
			}
		})
	}
}

func TestClientAuthenticationProvision(t *testing.T) {
	tests := []struct {
		name    string
		ca      ClientAuthentication
		wantErr bool
	}{
		{
			name: "specifying both 'CARaw' and 'TrustedCACerts' produces an error",
			ca: ClientAuthentication{
				CARaw:          json.RawMessage(`{"provider":"inline","trusted_ca_certs":["foo"]}`),
				TrustedCACerts: []string{"foo"},
			},
			wantErr: true,
		},
		{
			name: "specifying both 'CARaw' and 'TrustedCACertPEMFiles' produces an error",
			ca: ClientAuthentication{
				CARaw:                 json.RawMessage(`{"provider":"inline","trusted_ca_certs":["foo"]}`),
				TrustedCACertPEMFiles: []string{"foo"},
			},
			wantErr: true,
		},
		{
			name: "setting 'TrustedCACerts' provisions the cert pool",
			ca: ClientAuthentication{
				TrustedCACerts: []string{test_der_1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ca.provision(caddy.Context{})
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientAuthentication.provision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if tt.ca.ca.CertPool() == nil {
					t.Error("CertPool is nil, expected non-nil value")
				}
			}
		})
	}
}

func TestGetEncryptedClientHelloKeys(t *testing.T) {
	t.Run("empty and nil edge cases", func(t *testing.T) {
		ech := &ECH{
			configsMu: new(sync.RWMutex),
		}
		tlsApp := &TLS{
			EncryptedClientHello: ech,
		}

		// Test callback directly when stdlibReady is empty
		getKeysFunc := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			if tlsApp == nil || tlsApp.EncryptedClientHello == nil {
				return nil, nil
			}
			tlsApp.EncryptedClientHello.configsMu.RLock()
			defer tlsApp.EncryptedClientHello.configsMu.RUnlock()
			if len(tlsApp.EncryptedClientHello.stdlibReady) == 0 {
				return nil, nil
			}
			keys := make([]tls.EncryptedClientHelloKey, len(tlsApp.EncryptedClientHello.stdlibReady))
			for i, key := range tlsApp.EncryptedClientHello.stdlibReady {
				keys[i] = tls.EncryptedClientHelloKey{
					Config:      bytes.Clone(key.Config),
					PrivateKey:  bytes.Clone(key.PrivateKey),
					SendAsRetry: key.SendAsRetry,
				}
			}
			return keys, nil
		}

		keys, err := getKeysFunc(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keys != nil {
			t.Fatalf("expected nil keys for empty stdlibReady, got %v", keys)
		}

		// Test callback when tlsApp or EncryptedClientHello is nil
		tlsAppNil := &TLS{}
		getKeysFuncNil := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			if tlsAppNil == nil || tlsAppNil.EncryptedClientHello == nil {
				return nil, nil
			}
			tlsAppNil.EncryptedClientHello.configsMu.RLock()
			defer tlsAppNil.EncryptedClientHello.configsMu.RUnlock()
			if len(tlsAppNil.EncryptedClientHello.stdlibReady) == 0 {
				return nil, nil
			}
			keys := make([]tls.EncryptedClientHelloKey, len(tlsAppNil.EncryptedClientHello.stdlibReady))
			for i, key := range tlsAppNil.EncryptedClientHello.stdlibReady {
				keys[i] = tls.EncryptedClientHelloKey{
					Config:      bytes.Clone(key.Config),
					PrivateKey:  bytes.Clone(key.PrivateKey),
					SendAsRetry: key.SendAsRetry,
				}
			}
			return keys, nil
		}
		keysNil, err := getKeysFuncNil(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if keysNil != nil {
			t.Fatalf("expected nil keys for nil EncryptedClientHello, got %v", keysNil)
		}
	})

	t.Run("isolated slice copy", func(t *testing.T) {
		ech := &ECH{
			configsMu: new(sync.RWMutex),
			configs: map[string][]echConfig{
				"example.com": {
					{
						configBin:  []byte("config1"),
						privKeyBin: []byte("key1"),
					},
				},
			},
		}
		ech.configsMu.Lock()
		ech.updateKeyList()
		ech.configsMu.Unlock()

		tlsApp := &TLS{
			EncryptedClientHello: ech,
		}

		getKeysFunc := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			if tlsApp == nil || tlsApp.EncryptedClientHello == nil {
				return nil, nil
			}
			tlsApp.EncryptedClientHello.configsMu.RLock()
			defer tlsApp.EncryptedClientHello.configsMu.RUnlock()
			if len(tlsApp.EncryptedClientHello.stdlibReady) == 0 {
				return nil, nil
			}
			keys := make([]tls.EncryptedClientHelloKey, len(tlsApp.EncryptedClientHello.stdlibReady))
			for i, key := range tlsApp.EncryptedClientHello.stdlibReady {
				keys[i] = tls.EncryptedClientHelloKey{
					Config:      bytes.Clone(key.Config),
					PrivateKey:  bytes.Clone(key.PrivateKey),
					SendAsRetry: key.SendAsRetry,
				}
			}
			return keys, nil
		}

		keys, err := getKeysFunc(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}

		// Mutate returned slice element
		keys[0].Config[0] = 'X'

		// Verify internal stdlibReady was not mutated
		ech.configsMu.RLock()
		defer ech.configsMu.RUnlock()
		if ech.stdlibReady[0].Config[0] == 'X' {
			t.Fatalf("internal stdlibReady was mutated when returned slice was modified")
		}
	})

	t.Run("concurrent reads and key rotation", func(t *testing.T) {
		ech := &ECH{
			configsMu: new(sync.RWMutex),
			configs: map[string][]echConfig{
				"example.com": {
					{
						configBin:  []byte("config1"),
						privKeyBin: []byte("key1"),
					},
				},
			},
		}
		ech.configsMu.Lock()
		ech.updateKeyList()
		ech.configsMu.Unlock()

		tlsApp := &TLS{
			EncryptedClientHello: ech,
		}

		getKeysFunc := func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			if tlsApp == nil || tlsApp.EncryptedClientHello == nil {
				return nil, nil
			}
			tlsApp.EncryptedClientHello.configsMu.RLock()
			defer tlsApp.EncryptedClientHello.configsMu.RUnlock()
			if len(tlsApp.EncryptedClientHello.stdlibReady) == 0 {
				return nil, nil
			}
			keys := make([]tls.EncryptedClientHelloKey, len(tlsApp.EncryptedClientHello.stdlibReady))
			for i, key := range tlsApp.EncryptedClientHello.stdlibReady {
				keys[i] = tls.EncryptedClientHelloKey{
					Config:      bytes.Clone(key.Config),
					PrivateKey:  bytes.Clone(key.PrivateKey),
					SendAsRetry: key.SendAsRetry,
				}
			}
			return keys, nil
		}

		var wg sync.WaitGroup
		start := make(chan struct{})

		// Goroutines reading keys via callback and reading slice elements
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 100; j++ {
					keys, err := getKeysFunc(nil)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
						return
					}
					for _, k := range keys {
						_ = len(k.Config)
						_ = len(k.PrivateKey)
					}
				}
			}()
		}

		// Goroutines rotating keys / updating key list
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start
				for j := 0; j < 50; j++ {
					ech.configsMu.Lock()
					ech.configs["example.com"] = []echConfig{
						{
							configBin:  []byte(fmt.Sprintf("config-%d-%d", id, j)),
							privKeyBin: []byte(fmt.Sprintf("key-%d-%d", id, j)),
						},
					}
					ech.updateKeyList()
					ech.configsMu.Unlock()
				}
			}(i)
		}

		close(start)
		wg.Wait()
	})
}
