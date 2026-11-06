package maphandler

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestParseCaddyfile(t *testing.T) {
	testCases := []struct {
		name      string
		caddyfile string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid map destination",
			caddyfile: `map {path} {my_custom_dest} {
				/foo bar
			}`,
			wantErr: false,
		},
		{
			name: "static shorthand destination collision",
			caddyfile: `map {path} {http.request.host} {
				/foo bar
			}`,
			wantErr:   true,
			errSubstr: "destination {host} conflicts with a Caddyfile placeholder shorthand",
		},
		{
			name: "complex shorthand header destination collision",
			caddyfile: `map {path} {http.request.header.X-Header} {
				/foo bar
			}`,
			wantErr:   true,
			errSubstr: "destination {header.X-Header} conflicts with a Caddyfile placeholder shorthand",
		},
		{
			name: "complex shorthand vars destination collision",
			caddyfile: `map {path} {http.vars.myvar} {
				/foo bar
			}`,
			wantErr:   true,
			errSubstr: "destination {vars.myvar} conflicts with a Caddyfile placeholder shorthand",
		},
		{
			name: "complex shorthand file destination collision",
			caddyfile: `map {path} {http.request.uri.path.file.ext} {
				/foo bar
			}`,
			wantErr:   true,
			errSubstr: "destination {file.ext} conflicts with a Caddyfile placeholder shorthand",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tc.caddyfile)
			helper := httpcaddyfile.Helper{Dispenser: dispenser}

			_, err := parseCaddyfile(helper)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
