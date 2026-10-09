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
		// Dotted shorthand keys
		{
			name:     "header shorthand with dots",
			input:    "{header.X-Custom.Header}",
			expected: "{http.request.header.X-Custom.Header}",
		},
		{
			name:     "cookie shorthand with dots",
			input:    "{cookie.session.id.v2}",
			expected: "{http.request.cookie.session.id.v2}",
		},
		{
			name:     "labels shorthand with dots",
			input:    "{labels.sub.domain}",
			expected: "{http.request.host.labels.sub.domain}",
		},
		{
			name:     "path shorthand with dots",
			input:    "{path.sub.path}",
			expected: "{http.request.uri.path.sub.path}",
		},
		{
			name:     "query shorthand with dots",
			input:    "{query.filter.by.type}",
			expected: "{http.request.uri.query.filter.by.type}",
		},
		{
			name:     "regexp shorthand with dots",
			input:    "{re.group.1.name}",
			expected: "{http.regexp.group.1.name}",
		},
		{
			name:     "vars shorthand with dots",
			input:    "{vars.my.custom.var}",
			expected: "{http.vars.my.custom.var}",
		},
		{
			name:     "reverse proxy shorthand with dots",
			input:    "{rp.upstream.host.name}",
			expected: "{http.reverse_proxy.upstream.host.name}",
		},
		{
			name:     "response shorthand with dots",
			input:    "{resp.header.Custom.Header}",
			expected: "{http.intercept.header.Custom.Header}",
		},
		{
			name:     "error shorthand with dots",
			input:    "{err.status.code.detail}",
			expected: "{http.error.status.code.detail}",
		},
		{
			name:     "file_match shorthand with dots",
			input:    "{file_match.relative.path}",
			expected: "{http.matchers.file.relative.path}",
		},

		// Standard non-dotted shorthands
		{
			name:     "header shorthand simple",
			input:    "{header.User-Agent}",
			expected: "{http.request.header.User-Agent}",
		},
		{
			name:     "vars shorthand simple",
			input:    "{vars.foo_bar}",
			expected: "{http.vars.foo_bar}",
		},

		// Scalar file shorthands
		{
			name:     "scalar file shorthand",
			input:    "{file}",
			expected: "{http.request.uri.path.file}",
		},
		{
			name:     "scalar orig_file shorthand",
			input:    "{orig_file}",
			expected: "{http.request.orig_uri.path.file}",
		},

		// Global file placeholders preserved
		{
			name:     "global file placeholder absolute path",
			input:    "{file./etc/secret}",
			expected: "{file./etc/secret}",
		},
		{
			name:     "global file placeholder relative filename",
			input:    "{file.secret.txt}",
			expected: "{file.secret.txt}",
		},
		{
			name:     "global file placeholder simple key",
			input:    "{file.path}",
			expected: "{file.path}",
		},

		// Combination in a single string
		{
			name:     "combination of dotted header and global file placeholder",
			input:    "respond {header.X-Custom.Header} {file./etc/secret}",
			expected: "respond {http.request.header.X-Custom.Header} {file./etc/secret}",
		},
	}

	replacer := NewShorthandReplacer()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			segment := caddyfile.Segment{
				{Text: tc.input},
			}
			replacer.ApplyToSegment(&segment)

			if len(segment) != 1 {
				t.Fatalf("expected 1 token in segment, got %d", len(segment))
			}
			if segment[0].Text != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, segment[0].Text)
			}
		})
	}
}
