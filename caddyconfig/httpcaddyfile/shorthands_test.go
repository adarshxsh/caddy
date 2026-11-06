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
		{
			name:     "global file placeholders remain unchanged",
			input:    "{file.token} {file./var/secret} {file.path}",
			expected: "{file.token} {file./var/secret} {file.path}",
		},
		{
			name:     "http file sub-keys base and ext expand",
			input:    "{file.base} {file.ext}",
			expected: "{http.request.uri.path.file.base} {http.request.uri.path.file.ext}",
		},
		{
			name:     "simple file shorthand expands",
			input:    "{file}",
			expected: "{http.request.uri.path.file}",
		},
		{
			name:     "dotted header placeholder expands",
			input:    "{header.X-Custom.Header}",
			expected: "{http.request.header.X-Custom.Header}",
		},
		{
			name:     "dotted query and vars placeholders expand",
			input:    "{query.page.num} {vars.user.id}",
			expected: "{http.request.uri.query.page.num} {http.vars.user.id}",
		},
		{
			name:     "placeholders with hyphens, underscores, slashes, and numbers",
			input:    "{cookie.user_session} {path.sub/dir} {re.match.1} {rp.up-stream.1} {resp.header.val} {err.status.code} {file_match.key_1}",
			expected: "{http.request.cookie.user_session} {http.request.uri.path.sub/dir} {http.regexp.match.1} {http.reverse_proxy.up-stream.1} {http.intercept.header.val} {http.error.status.code} {http.matchers.file.key_1}",
		},
		{
			name:     "unclosed brace does not swallow subsequent tokens",
			input:    "{header.X-Custom and {query.page}",
			expected: "{header.X-Custom and {http.request.uri.query.page}",
		},
	}

	replacer := NewShorthandReplacer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment := caddyfile.Segment{
				caddyfile.Token{Text: tt.input},
			}
			replacer.ApplyToSegment(&segment)
			if len(segment) > 0 && segment[0].Text != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, segment[0].Text)
			}
		})
	}
}
