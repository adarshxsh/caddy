package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacerDefaults(t *testing.T) {
	replacer := NewShorthandReplacer()

	tests := []struct {
		input  string
		expect string
	}{
		// Simple shorthands without defaults
		{input: "{host}", expect: "{http.request.host}"},
		{input: "{port}", expect: "{http.request.port}"},
		{input: "{path}", expect: "{http.request.uri.path}"},
		{input: "{query}", expect: "{http.request.uri.query}"},
		{input: "{dir}", expect: "{http.request.uri.path.dir}"},
		{input: "{file}", expect: "{http.request.uri.path.file}"},

		// Simple shorthands with defaults
		{input: "{host:default.com}", expect: "{http.request.host:default.com}"},
		{input: "{port:8080}", expect: "{http.request.port:8080}"},
		{input: "{path:/index.html}", expect: "{http.request.uri.path:/index.html}"},
		{input: "{query:a=b}", expect: "{http.request.uri.query:a=b}"},
		{input: "{?query:a=b}", expect: "{http.request.uri.prefixed_query:a=b}"},
		{input: "{remote_host:127.0.0.1}", expect: "{http.request.remote.host:127.0.0.1}"},

		// Complex shorthands without defaults
		{input: "{header.X-Custom}", expect: "{http.request.header.X-Custom}"},
		{input: "{cookie.session}", expect: "{http.request.cookie.session}"},
		{input: "{labels.0}", expect: "{http.request.host.labels.0}"},
		{input: "{path.0}", expect: "{http.request.uri.path.0}"},
		{input: "{query.search}", expect: "{http.request.uri.query.search}"},
		{input: "{re.0}", expect: "{http.regexp.0}"},
		{input: "{vars.my_var}", expect: "{http.vars.my_var}"},
		{input: "{rp.upstream}", expect: "{http.reverse_proxy.upstream}"},
		{input: "{resp.header}", expect: "{http.intercept.header}"},
		{input: "{err.status_code}", expect: "{http.error.status_code}"},

		// Complex shorthands with defaults
		{input: "{header.X-Custom:fallback}", expect: "{http.request.header.X-Custom:fallback}"},
		{input: "{cookie.session:anon}", expect: "{http.request.cookie.session:anon}"},
		{input: "{labels.0:www}", expect: "{http.request.host.labels.0:www}"},
		{input: "{path.0:index}", expect: "{http.request.uri.path.0:index}"},
		{input: "{query.search:none}", expect: "{http.request.uri.query.search:none}"},
		{input: "{re.0:default_match}", expect: "{http.regexp.0:default_match}"},
		{input: "{vars.my_var:123}", expect: "{http.vars.my_var:123}"},
		{input: "{err.status_code:500}", expect: "{http.error.status_code:500}"},

		// Mixed text and multiple placeholders
		{
			input:  "Host: {host:example.com}, Header: {header.X-Forwarded-Host:default.local}",
			expect: "Host: {http.request.host:example.com}, Header: {http.request.header.X-Forwarded-Host:default.local}",
		},
	}

	for i, tc := range tests {
		segment := caddyfile.Segment{
			caddyfile.Token{Text: tc.input},
		}
		replacer.ApplyToSegment(&segment)
		if segment[0].Text != tc.expect {
			t.Errorf("Test %d failed: input %q, expected %q, got %q", i, tc.input, tc.expect, segment[0].Text)
		}
	}
}
