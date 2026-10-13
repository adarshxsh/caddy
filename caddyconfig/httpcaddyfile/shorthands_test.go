package httpcaddyfile

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Static file shorthands
		{"{file}", "{http.request.uri.path.file}"},
		{"{file.base}", "{http.request.uri.path.file.base}"},
		{"{file.ext}", "{http.request.uri.path.file.ext}"},

		// Global file placeholders preserved
		{"{file.token}", "{file.token}"},
		{"{file./etc/hosts}", "{file./etc/hosts}"},
		{"{file.secret.txt}", "{file.secret.txt}"},

		// Dotted key complex shorthands
		{"{header.X-Custom.Header}", "{http.request.header.X-Custom.Header}"},
		{"{cookie.my.session.id}", "{http.request.cookie.my.session.id}"},
		{"{labels.1.2}", "{http.request.host.labels.1.2}"},
		{"{path.sub.dir}", "{http.request.uri.path.sub.dir}"},
		{"{query.page.num}", "{http.request.uri.query.page.num}"},
		{"{re.0.sub}", "{http.regexp.0.sub}"},
		{"{vars.my.app.setting}", "{http.vars.my.app.setting}"},
		{"{rp.upstream.addr}", "{http.reverse_proxy.upstream.addr}"},
		{"{resp.status.code}", "{http.intercept.status.code}"},
		{"{err.status_code}", "{http.error.status_code}"},
		{"{file_match.some.key}", "{http.matchers.file.some.key}"},
	}

	replacer := NewShorthandReplacer()

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			segment := caddyfile.Segment{
				{Text: tt.input},
			}
			replacer.ApplyToSegment(&segment)
			if segment[0].Text != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, segment[0].Text)
			}
		})
	}
}

func TestShorthandsInCaddyfileAdaptation(t *testing.T) {
	caddyfileInput := `
http://localhost {
	respond {file.token}
	respond {file.base}
	respond {file.ext}
	respond {header.X-Custom.Header}
	respond {query.page.num}
	respond {vars.my.app.setting}
}
`

	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}

	jsonBytes, _, err := adapter.Adapt([]byte(caddyfileInput), nil)
	if err != nil {
		t.Fatalf("Adapt failed: %v", err)
	}

	jsonStr := string(jsonBytes)

	expectedStrings := []string{
		"{file.token}",
		"{http.request.uri.path.file.base}",
		"{http.request.uri.path.file.ext}",
		"{http.request.header.X-Custom.Header}",
		"{http.request.uri.query.page.num}",
		"{http.vars.my.app.setting}",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("Expected JSON output to contain %q, but got:\n%s", expected, jsonStr)
		}
	}
}
