package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestWasReplacedPlaceholderShorthand(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		// Static shorthands
		{"{http.request.host}", "{host}"},
		{"http.request.host", "{host}"},
		{"{http.request.method}", "{method}"},
		{"http.request.method", "{method}"},
		{"{http.request.uri.path.file}", "{file}"},
		{"http.request.uri.path.file", "{file}"},

		// Complex shorthands (all 12 categories)
		{"{http.request.header.X-Header}", "{header.X-Header}"},
		{"http.request.header.X-Header", "{header.X-Header}"},
		{"{http.request.cookie.session}", "{cookie.session}"},
		{"http.request.cookie.session", "{cookie.session}"},
		{"{http.request.host.labels.1}", "{labels.1}"},
		{"http.request.host.labels.1", "{labels.1}"},
		{"{http.request.uri.path.file.ext}", "{file.ext}"},
		{"http.request.uri.path.file.ext", "{file.ext}"},
		{"{http.request.uri.path.my-path}", "{path.my-path}"},
		{"http.request.uri.path.my-path", "{path.my-path}"},
		{"{http.request.uri.query.param}", "{query.param}"},
		{"http.request.uri.query.param", "{query.param}"},
		{"{http.regexp.match.1}", "{re.match.1}"},
		{"http.regexp.match.1", "{re.match.1}"},
		{"{http.vars.myvar}", "{vars.myvar}"},
		{"http.vars.myvar", "{vars.myvar}"},
		{"{http.reverse_proxy.upstream.address}", "{rp.upstream.address}"},
		{"http.reverse_proxy.upstream.address", "{rp.upstream.address}"},
		{"{http.intercept.status}", "{resp.status}"},
		{"http.intercept.status", "{resp.status}"},
		{"{http.error.status_code}", "{err.status_code}"},
		{"http.error.status_code", "{err.status_code}"},
		{"{http.matchers.file.relative}", "{file_match.relative}"},
		{"http.matchers.file.relative", "{file_match.relative}"},

		// Non-shorthand placeholders and normal tokens
		{"{custom_var}", ""},
		{"custom_var", ""},
		{"{http.request.unknown}", ""},
		{"http.request.unknown", ""},
	}

	for i, tc := range testCases {
		actual := WasReplacedPlaceholderShorthand(tc.input)
		if actual != tc.expected {
			t.Errorf("Test %d: input %q, expected %q, got %q", i, tc.input, tc.expected, actual)
		}
	}
}

func TestShorthandReplacer(t *testing.T) {
	replacer := NewShorthandReplacer()

	segment := caddyfile.Segment{
		caddyfile.Token{Text: "header_test"},
		caddyfile.Token{Text: "{header.X-Custom}"},
		caddyfile.Token{Text: "{file.ext}"},
		caddyfile.Token{Text: "{host}"},
	}

	replacer.ApplyToSegment(&segment)

	expected := []string{
		"header_test",
		"{http.request.header.X-Custom}",
		"{http.request.uri.path.file.ext}",
		"{http.request.host}",
	}

	for i, exp := range expected {
		if segment[i].Text != exp {
			t.Errorf("Token %d: expected %q, got %q", i, exp, segment[i].Text)
		}
	}
}
