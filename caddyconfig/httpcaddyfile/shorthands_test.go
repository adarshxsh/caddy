package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacer(t *testing.T) {
	replacer := NewShorthandReplacer()

	tests := []struct {
		input    string
		expected string
	}{
		// Scalar file shorthands
		{"{file}", "{http.request.uri.path.file}"},
		{"{orig_file}", "{http.request.orig_uri.path.file}"},

		// Global file placeholders must remain uncorrupted
		{"{file.path}", "{file.path}"},
		{"{file./etc/passwd}", "{file./etc/passwd}"},
		{"{file.config.json}", "{file.config.json}"},

		// Dotted header and query shorthands
		{"{header.X-Custom.Header}", "{http.request.header.X-Custom.Header}"},
		{"{header.Content-Type}", "{http.request.header.Content-Type}"},
		{"{header.a.b.c}", "{http.request.header.a.b.c}"},
		{"{query.user.name}", "{http.request.uri.query.user.name}"},
		{"{query.p.q.r}", "{http.request.uri.query.p.q.r}"},

		// Dotted cookies, labels, path, vars, etc.
		{"{cookie.session.id}", "{http.request.cookie.session.id}"},
		{"{labels.0.1}", "{http.request.host.labels.0.1}"},
		{"{path.dir.file}", "{http.request.uri.path.dir.file}"},
		{"{re.name.0}", "{http.regexp.name.0}"},
		{"{vars.my.var.name}", "{http.vars.my.var.name}"},
		{"{rp.header.X-Retry}", "{http.reverse_proxy.header.X-Retry}"},
		{"{resp.header.Location}", "{http.intercept.header.Location}"},
		{"{err.status_code.value}", "{http.error.status_code.value}"},
		{"{file_match.rule.1}", "{http.matchers.file.rule.1}"},

		// Standard non-dotted shorthands remain unaffected
		{"{host}", "{http.request.host}"},
		{"{path}", "{http.request.uri.path}"},
		{"{method}", "{http.request.method}"},
		{"{header.Host}", "{http.request.header.Host}"},
		{"{query.q}", "{http.request.uri.query.q}"},

		// Mixed text in segment token
		{"hello {header.X-Custom.Header} world", "hello {http.request.header.X-Custom.Header} world"},
		{"read {file.path} for {query.user.name}", "read {file.path} for {http.request.uri.query.user.name}"},
	}

	for i, tc := range tests {
		segment := caddyfile.Segment{
			{Text: tc.input},
		}
		replacer.ApplyToSegment(&segment)
		if got := segment[0].Text; got != tc.expected {
			t.Errorf("test %d: input %q: expected %q, got %q", i, tc.input, tc.expected, got)
		}
	}
}
