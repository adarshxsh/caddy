package httpcaddyfile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestMatcherSyntax(t *testing.T) {
	for i, tc := range []struct {
		input          string
		expectError    bool
		expectContains string
	}{
		{
			input: `http://localhost
			@debug {
				query showdebug=1
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
				query bad format
			}
			`,
			expectError: true,
		},
		{
			input: `http://localhost
			@debug {
				not {
					path /somepath*
				}
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
				not path /somepath*
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug not path /somepath*
			`,
			expectError: false,
		},
		{
			input: `http://localhost {
				@test {
					path /test
				}
				@test {
					path /other
				}
				respond @test "hello"
			}
			`,
			expectError:    true,
			expectContains: "is defined more than once",
		},
		{
			input: `(snippet) {
				@{args[0]} {
					path /{args[0]}
				}
				respond @{args[0]} "hello"
			}
			http://localhost {
				import snippet foo
				import snippet bar
			}
			`,
			expectError: false,
		},
		{
			input: `@matcher {
				path /matcher-not-allowed/outside-of-site-block/*
			}
			http://localhost
			`,
			expectError: true,
		},
		{
			input: `http://localhost {
				@m "a == b" path /api/*
				respond @m "hello"
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost {
				@m {
					"a == b"
					path /api/*
				}
				respond @m "hello"
			}
			`,
			expectError: false,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}

		if err != nil && tc.expectContains != "" {
			if !strings.Contains(err.Error(), tc.expectContains) {
				t.Errorf("Test %d error message mismatch: expected to contain %q, got %q",
					i, tc.expectContains, err.Error())
			}
		}
	}
}

func TestSpecificity(t *testing.T) {
	for i, tc := range []struct {
		input  string
		expect int
	}{
		{"", 0},
		{"*", 0},
		{"*.*", 1},
		{"{placeholder}", 0},
		{"/{placeholder}", 1},
		{"foo", 3},
		{"example.com", 11},
		{"a.example.com", 13},
		{"*.example.com", 12},
		{"/foo", 4},
		{"/foo*", 4},
		{"{placeholder}.example.com", 12},
		{"{placeholder.example.com", 24},
		{"}.", 2},
		{"}{", 2},
		{"{}", 0},
		{"{{{}}", 1},
	} {
		actual := specificity(tc.input)
		if actual != tc.expect {
			t.Errorf("Test %d (%s): Expected %d but got %d", i, tc.input, tc.expect, actual)
		}
	}
}

func TestGlobalOptions(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectError bool
	}{
		{
			input: `
				{
					email test@example.com
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin off
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 127.0.0.1:2020
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin {
						disabled false
					}
				}
				:80
			`,
			expectError: true,
		},
		{
			input: `
				{
					admin {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 127.0.0.1:2020 {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 192.168.1.1:2020 127.0.0.1:2020 {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: true,
		},
		{
			input: `
				{
					admin off {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: true,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}
	}
}

func TestDefaultSNIWithoutHTTPS(t *testing.T) {
	caddyfileStr := `{
		default_sni my-sni.com
	}
	example.com {
	}`

	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}

	result, _, err := adapter.Adapt([]byte(caddyfileStr), nil)
	if err != nil {
		t.Fatalf("Failed to adapt Caddyfile: %v", err)
	}

	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]*caddyhttp.Server `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	if err := json.Unmarshal(result, &config); err != nil {
		t.Fatalf("Failed to unmarshal JSON config: %v", err)
	}

	server, ok := config.Apps.HTTP.Servers["srv0"]
	if !ok {
		t.Fatalf("Expected server 'srv0' to be created")
	}

	if len(server.TLSConnPolicies) == 0 {
		t.Fatalf("Expected TLS connection policies to be generated, got none")
	}

	found := false
	for _, policy := range server.TLSConnPolicies {
		if policy.DefaultSNI == "my-sni.com" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected default_sni 'my-sni.com' in TLS connection policies, but it was missing. Generated JSON: %s", string(result))
	}
}

func TestNamedMatcherQuotedExpressionWithTrailingMatchers(t *testing.T) {
	testCases := []struct {
		name      string
		caddyfile string
	}{
		{
			name: "inline quoted expression with trailing path matcher",
			caddyfile: `http://localhost {
				@m "a == b" path /api/*
				respond @m "hello"
			}`,
		},
		{
			name: "block quoted expression with trailing path matcher",
			caddyfile: `http://localhost {
				@m {
					"a == b"
					path /api/*
				}
				respond @m "hello"
			}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := caddyfile.Adapter{
				ServerType: ServerType{},
			}

			result, _, err := adapter.Adapt([]byte(tc.caddyfile), nil)
			if err != nil {
				t.Fatalf("Failed to adapt Caddyfile: %v", err)
			}

			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Routes []struct {
								Handle []struct {
									Routes []struct {
										Match []map[string]any `json:"match"`
									} `json:"routes"`
								} `json:"handle"`
							} `json:"routes"`
						} `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}

			if err := json.Unmarshal(result, &config); err != nil {
				t.Fatalf("Failed to unmarshal JSON config: %v", err)
			}

			server, ok := config.Apps.HTTP.Servers["srv0"]
			if !ok {
				t.Fatalf("Expected server 'srv0' to be created")
			}

			if len(server.Routes) == 0 || len(server.Routes[0].Handle) == 0 ||
				len(server.Routes[0].Handle[0].Routes) == 0 ||
				len(server.Routes[0].Handle[0].Routes[0].Match) == 0 {
				t.Fatalf("Expected route with subroute matchers, got none. Generated JSON: %s", string(result))
			}

			matcherSet := server.Routes[0].Handle[0].Routes[0].Match[0]
			if _, hasExpr := matcherSet["expression"]; !hasExpr {
				t.Errorf("Expected matcher set to contain 'expression', but it was missing. Matcher set: %v", matcherSet)
			}
			if _, hasPath := matcherSet["path"]; !hasPath {
				t.Errorf("Expected matcher set to contain 'path', but it was missing. Matcher set: %v", matcherSet)
			}
		})
	}
}
