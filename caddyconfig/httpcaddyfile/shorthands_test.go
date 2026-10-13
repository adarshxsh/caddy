package httpcaddyfile

import (
	"testing"
)

func TestWasReplacedPlaceholderShorthand(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		// Static shorthands
		{input: "{http.request.host}", expected: "{host}"},
		{input: "http.request.host", expected: "{host}"},
		{input: "{http.request.method}", expected: "{method}"},
		{input: "{http.vars.client_ip}", expected: "{client_ip}"},
		{input: "{http.request.uri.path.dir}", expected: "{dir}"},
		{input: "{http.request.uri.path.file}", expected: "{file}"},

		// Complex shorthands (12 categories)
		// 1. header
		{input: "{http.request.header.X-Test}", expected: "{header.X-Test}"},
		{input: "http.request.header.X-Test", expected: "{header.X-Test}"},

		// 2. cookie
		{input: "{http.request.cookie.session}", expected: "{cookie.session}"},
		{input: "http.request.cookie.session", expected: "{cookie.session}"},

		// 3. labels
		{input: "{http.request.host.labels.1}", expected: "{labels.1}"},
		{input: "http.request.host.labels.1", expected: "{labels.1}"},

		// 4. file (takes precedence over path)
		{input: "{http.request.uri.path.file.ext}", expected: "{file.ext}"},
		{input: "http.request.uri.path.file.ext", expected: "{file.ext}"},

		// 5. path
		{input: "{http.request.uri.path.subpath}", expected: "{path.subpath}"},
		{input: "http.request.uri.path.subpath", expected: "{path.subpath}"},

		// 6. query
		{input: "{http.request.uri.query.q}", expected: "{query.q}"},
		{input: "http.request.uri.query.q", expected: "{query.q}"},

		// 7. re
		{input: "{http.regexp.name.1}", expected: "{re.name.1}"},
		{input: "http.regexp.name.1", expected: "{re.name.1}"},

		// 8. vars
		{input: "{http.vars.custom_var}", expected: "{vars.custom_var}"},
		{input: "http.vars.custom_var", expected: "{vars.custom_var}"},

		// 9. rp
		{input: "{http.reverse_proxy.upstream}", expected: "{rp.upstream}"},
		{input: "http.reverse_proxy.upstream", expected: "{rp.upstream}"},

		// 10. resp
		{input: "{http.intercept.status}", expected: "{resp.status}"},
		{input: "http.intercept.status", expected: "{resp.status}"},

		// 11. err
		{input: "{http.error.status_code}", expected: "{err.status_code}"},
		{input: "http.error.status_code", expected: "{err.status_code}"},

		// 12. file_match
		{input: "{http.matchers.file.base}", expected: "{file_match.base}"},
		{input: "http.matchers.file.base", expected: "{file_match.base}"},

		// Non-matching tokens
		{input: "{http.unknown.placeholder}", expected: ""},
		{input: "something_else", expected: ""},
		{input: "", expected: ""},
	}

	for i, tc := range testCases {
		actual := WasReplacedPlaceholderShorthand(tc.input)
		if actual != tc.expected {
			t.Errorf("Test %d (%s): expected %q, got %q", i, tc.input, tc.expected, actual)
		}
	}
}
