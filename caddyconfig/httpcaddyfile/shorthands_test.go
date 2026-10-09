package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Simple shorthands without default values
		{
			name:     "simple host",
			input:    "{host}",
			expected: "{http.request.host}",
		},
		{
			name:     "simple port",
			input:    "{port}",
			expected: "{http.request.port}",
		},
		{
			name:     "simple uri",
			input:    "{uri}",
			expected: "{http.request.uri}",
		},
		{
			name:     "simple path",
			input:    "{path}",
			expected: "{http.request.uri.path}",
		},
		{
			name:     "simple query",
			input:    "{query}",
			expected: "{http.request.uri.query}",
		},
		{
			name:     "simple client_ip",
			input:    "{client_ip}",
			expected: "{http.vars.client_ip}",
		},

		// Simple shorthands with default values
		{
			name:     "simple host with default value",
			input:    "{host:localhost}",
			expected: "{http.request.host:localhost}",
		},
		{
			name:     "simple port with default value",
			input:    "{port:8080}",
			expected: "{http.request.port:8080}",
		},
		{
			name:     "simple uri with default value",
			input:    "{uri:/}",
			expected: "{http.request.uri:/}",
		},
		{
			name:     "simple path with default value",
			input:    "{path:/api}",
			expected: "{http.request.uri.path:/api}",
		},
		{
			name:     "simple query with default value",
			input:    "{query:page=1}",
			expected: "{http.request.uri.query:page=1}",
		},
		{
			name:     "simple host with default value containing colons",
			input:    "{host:localhost:8080}",
			expected: "{http.request.host:localhost:8080}",
		},

		// Complex shorthands without default values
		{
			name:     "complex header",
			input:    "{header.User-Agent}",
			expected: "{http.request.header.User-Agent}",
		},
		{
			name:     "complex cookie",
			input:    "{cookie.session_id}",
			expected: "{http.request.cookie.session_id}",
		},
		{
			name:     "complex labels",
			input:    "{labels.0}",
			expected: "{http.request.host.labels.0}",
		},
		{
			name:     "complex path",
			input:    "{path.0}",
			expected: "{http.request.uri.path.0}",
		},
		{
			name:     "complex file",
			input:    "{file.ext}",
			expected: "{http.request.uri.path.file.ext}",
		},
		{
			name:     "complex query",
			input:    "{query.id}",
			expected: "{http.request.uri.query.id}",
		},
		{
			name:     "complex re",
			input:    "{re.name.0}",
			expected: "{http.regexp.name.0}",
		},
		{
			name:     "complex vars",
			input:    "{vars.foo}",
			expected: "{http.vars.foo}",
		},
		{
			name:     "complex rp",
			input:    "{rp.upstream}",
			expected: "{http.reverse_proxy.upstream}",
		},
		{
			name:     "complex resp",
			input:    "{resp.status}",
			expected: "{http.intercept.status}",
		},
		{
			name:     "complex err",
			input:    "{err.status_code}",
			expected: "{http.error.status_code}",
		},
		{
			name:     "complex file_match",
			input:    "{file_match.key}",
			expected: "{http.matchers.file.key}",
		},

		// Complex shorthands with default values
		{
			name:     "complex header with default value",
			input:    "{header.User-Agent:unknown}",
			expected: "{http.request.header.User-Agent:unknown}",
		},
		{
			name:     "complex vars with default value",
			input:    "{vars.foo:bar}",
			expected: "{http.vars.foo:bar}",
		},
		{
			name:     "complex query with default value",
			input:    "{query.id:0}",
			expected: "{http.request.uri.query.id:0}",
		},
		{
			name:     "complex vars with default value containing colons",
			input:    "{vars.url:http://localhost:8080}",
			expected: "{http.vars.url:http://localhost:8080}",
		},
		{
			name:     "complex header with default value containing multiple colons",
			input:    "{header.X-Custom:a:b:c}",
			expected: "{http.request.header.X-Custom:a:b:c}",
		},

		// Non-matching or mixed
		{
			name:     "string without placeholders",
			input:    "plain_text",
			expected: "plain_text",
		},
		{
			name:     "unsupported shorthand with default value",
			input:    "{unknown:default}",
			expected: "{unknown:default}",
		},
		{
			name:     "multiple shorthands in one string",
			input:    "http://{host:localhost}:{port:8080}{path:/api}",
			expected: "http://{http.request.host:localhost}:{http.request.port:8080}{http.request.uri.path:/api}",
		},
	}

	replacer := NewShorthandReplacer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment := caddyfile.Segment{
				{Text: tt.input},
			}
			replacer.ApplyToSegment(&segment)
			if actual := segment[0].Text; actual != tt.expected {
				t.Errorf("ApplyToSegment(%q) = %q, want %q", tt.input, actual, tt.expected)
			}
		})
	}
}
