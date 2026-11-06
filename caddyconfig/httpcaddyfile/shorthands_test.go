package httpcaddyfile

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacer(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "simple shorthands without default values",
			input:    []string{"{host}", "{path}", "{client_ip}", "{query}", "{uri}", "{dir}", "{remote}"},
			expected: []string{"{http.request.host}", "{http.request.uri.path}", "{http.vars.client_ip}", "{http.request.uri.query}", "{http.request.uri}", "{http.request.uri.path.dir}", "{http.request.remote}"},
		},
		{
			name:     "simple shorthands with default values",
			input:    []string{"{host:example.com}", "{client_ip:127.0.0.1}", "{path:/default}", "{query:search=caddy}", "{uri:/home}", "{dir:/var/www}", "{remote:10.0.0.1}"},
			expected: []string{"{http.request.host:example.com}", "{http.vars.client_ip:127.0.0.1}", "{http.request.uri.path:/default}", "{http.request.uri.query:search=caddy}", "{http.request.uri:/home}", "{http.request.uri.path.dir:/var/www}", "{http.request.remote:10.0.0.1}"},
		},
		{
			name:     "complex shorthands without default values",
			input:    []string{"{header.User-Agent}", "{cookie.session}", "{query.q}", "{vars.my_var}", "{re.group.1}", "{err.status_code}"},
			expected: []string{"{http.request.header.User-Agent}", "{http.request.cookie.session}", "{http.request.uri.query.q}", "{http.vars.my_var}", "{http.regexp.group.1}", "{http.error.status_code}"},
		},
		{
			name:     "complex shorthands with default values",
			input:    []string{"{header.User-Agent:unknown}", "{cookie.session:none}", "{query.q:caddy}", "{vars.my_var:fallback}", "{re.group.1:val}", "{err.status_code:500}"},
			expected: []string{"{http.request.header.User-Agent:unknown}", "{http.request.cookie.session:none}", "{http.request.uri.query.q:caddy}", "{http.vars.my_var:fallback}", "{http.regexp.group.1:val}", "{http.error.status_code:500}"},
		},
		{
			name:     "mixed shorthands with and without defaults in a segment",
			input:    []string{"header_up", "Host", "{host:fallback.com}", "User-Agent", "{header.User-Agent:unknown}", "Path", "{path}"},
			expected: []string{"header_up", "Host", "{http.request.host:fallback.com}", "User-Agent", "{http.request.header.User-Agent:unknown}", "Path", "{http.request.uri.path}"},
		},
		{
			name:     "non-shorthands and env placeholders left intact",
			input:    []string{"{http.request.host}", "{env.MY_VAR:default_val}", "static_text"},
			expected: []string{"{http.request.host}", "{env.MY_VAR:default_val}", "static_text"},
		},
	}

	replacer := NewShorthandReplacer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment := make(caddyfile.Segment, len(tt.input))
			for i, str := range tt.input {
				segment[i] = caddyfile.Token{Text: str}
			}

			replacer.ApplyToSegment(&segment)

			for i, token := range segment {
				if token.Text != tt.expected[i] {
					t.Errorf("token %d: expected %q, got %q", i, tt.expected[i], token.Text)
				}
			}
		})
	}
}

func TestShorthandAdaptation(t *testing.T) {
	caddyfileInput := `example.com {
	respond "Host: {host:example.com} UA: {header.User-Agent:unknown}"
}`

	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}
	jsonOutput, _, err := adapter.Adapt([]byte(caddyfileInput), map[string]any{})
	if err != nil {
		t.Fatalf("Adapt failed: %v", err)
	}

	jsonStr := string(jsonOutput)
	if !strings.Contains(jsonStr, "{http.request.host:example.com}") {
		t.Errorf("Expected adapted JSON to contain {http.request.host:example.com}, got:\n%s", jsonStr)
	}
	if !strings.Contains(jsonStr, "{http.request.header.User-Agent:unknown}") {
		t.Errorf("Expected adapted JSON to contain {http.request.header.User-Agent:unknown}, got:\n%s", jsonStr)
	}
}
