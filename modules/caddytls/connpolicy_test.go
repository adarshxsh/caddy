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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

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

func TestGetEncryptedClientHelloKeys_Isolation(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {
				{
					configBin:  []byte("original_config"),
					privKeyBin: []byte("original_key"),
				},
			},
		},
	}
	ech.updateKeyList()

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": json.RawMessage(`{"encrypted_client_hello":{"configs":[{"public_name":"example.com"}]}}`),
		},
	}

	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext error: %v", err)
	}

	loadedTLS, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load TLS app: %v", err)
	}
	appTLS := loadedTLS.(*TLS)
	appTLS.EncryptedClientHello = ech

	policies := ConnectionPolicies{&ConnectionPolicy{}}
	tlsCfg := policies.TLSConfig(ctx)

	if tlsCfg.GetEncryptedClientHelloKeys == nil {
		t.Fatal("expected GetEncryptedClientHelloKeys to be non-nil")
	}

	keys1, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("GetEncryptedClientHelloKeys error: %v", err)
	}
	if len(keys1) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys1))
	}
	if string(keys1[0].Config) != "original_config" || string(keys1[0].PrivateKey) != "original_key" {
		t.Fatalf("unexpected key content: config=%s, key=%s", keys1[0].Config, keys1[0].PrivateKey)
	}

	// Mutate returned key slice elements and buffers
	keys1[0].Config[0] = 'X'
	keys1[0].PrivateKey[0] = 'Y'
	keys1[0].SendAsRetry = false
	keys1 = append(keys1, tls.EncryptedClientHelloKey{Config: []byte("extra")})

	// Fetch keys again and check internal stdlibReady state directly
	ech.configsMu.RLock()
	internalConfig := string(ech.stdlibReady[0].Config)
	internalKey := string(ech.stdlibReady[0].PrivateKey)
	internalRetry := ech.stdlibReady[0].SendAsRetry
	internalLen := len(ech.stdlibReady)
	ech.configsMu.RUnlock()

	if internalConfig != "original_config" {
		t.Errorf("internal config was mutated: got %s, want original_config", internalConfig)
	}
	if internalKey != "original_key" {
		t.Errorf("internal key was mutated: got %s, want original_key", internalKey)
	}
	if !internalRetry {
		t.Errorf("internal SendAsRetry was mutated: got false, want true")
	}
	if internalLen != 1 {
		t.Errorf("internal stdlibReady length was mutated: got %d, want 1", internalLen)
	}

	keys2, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("GetEncryptedClientHelloKeys second call error: %v", err)
	}
	if string(keys2[0].Config) != "original_config" || string(keys2[0].PrivateKey) != "original_key" {
		t.Errorf("subsequent call returned mutated buffers: config=%s, key=%s", keys2[0].Config, keys2[0].PrivateKey)
	}
}

func TestGetEncryptedClientHelloKeys_EdgeCases(t *testing.T) {
	// Case 1: empty stdlibReady
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs:   map[string][]echConfig{"example.com": {}},
	}
	ech.updateKeyList()

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": json.RawMessage(`{"encrypted_client_hello":{"configs":[{"public_name":"example.com"}]}}`),
		},
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext error: %v", err)
	}

	loadedTLS, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load TLS app: %v", err)
	}
	appTLS := loadedTLS.(*TLS)
	appTLS.EncryptedClientHello = ech

	policies := ConnectionPolicies{&ConnectionPolicy{}}
	tlsCfg := policies.TLSConfig(ctx)

	keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil keys for empty stdlibReady, got %v", keys)
	}

	// Case 2: nil EncryptedClientHello
	appTLS.EncryptedClientHello = nil
	keys, err = tlsCfg.GetEncryptedClientHelloKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil EncryptedClientHello: %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil keys for nil EncryptedClientHello, got %v", keys)
	}
}

func TestGetEncryptedClientHelloKeys_Concurrency(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"example.com": {
				{
					configBin:  []byte("config_initial"),
					privKeyBin: []byte("key_initial"),
				},
			},
		},
	}
	ech.updateKeyList()

	cfg := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"tls": json.RawMessage(`{"encrypted_client_hello":{"configs":[{"public_name":"example.com"}]}}`),
		},
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("ProvisionContext error: %v", err)
	}

	loadedTLS, err := ctx.App("tls")
	if err != nil {
		t.Fatalf("failed to load TLS app: %v", err)
	}
	appTLS := loadedTLS.(*TLS)
	appTLS.EncryptedClientHello = ech

	policies := ConnectionPolicies{&ConnectionPolicy{}}
	tlsCfg := policies.TLSConfig(ctx)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Writer goroutine: simulates key rotations/updates in ech
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				i++
				ech.configsMu.Lock()
				ech.configs["example.com"] = []echConfig{
					{
						configBin:  []byte(fmt.Sprintf("config_%d", i)),
						privKeyBin: []byte(fmt.Sprintf("key_%d", i)),
					},
				}
				ech.updateKeyList()
				ech.configsMu.Unlock()
				time.Sleep(10 * time.Microsecond)
			}
		}
	}()

	// Reader goroutines: simulate concurrent handshake key retrievals
	const numReaders = 10
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					keys, err := tlsCfg.GetEncryptedClientHelloKeys(nil)
					if err != nil {
						t.Errorf("GetEncryptedClientHelloKeys error: %v", err)
						return
					}
					if len(keys) > 0 {
						// Mutate read keys to test isolation under concurrency
						if len(keys[0].Config) > 0 {
							keys[0].Config[0] = 'A'
						}
						if len(keys[0].PrivateKey) > 0 {
							keys[0].PrivateKey[0] = 'B'
						}
					}
					time.Sleep(5 * time.Microsecond)
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}
