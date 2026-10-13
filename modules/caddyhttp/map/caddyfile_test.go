package maphandler

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestParseCaddyfileDestinationCollision(t *testing.T) {
	testCases := []struct {
		name      string
		caddyfile string
		wantErr   bool
	}{
		{
			name: "valid destination",
			caddyfile: `map {path} {my_dest} {
				/foo bar
			}`,
			wantErr: false,
		},
		{
			name: "header shorthand collision",
			caddyfile: `map {path} {http.request.header.X-Header} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "cookie shorthand collision",
			caddyfile: `map {path} {http.request.cookie.session} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "labels shorthand collision",
			caddyfile: `map {path} {http.request.host.labels.1} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "file shorthand collision",
			caddyfile: `map {path} {http.request.uri.path.file.ext} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "path shorthand collision",
			caddyfile: `map {path} {http.request.uri.path.subpath} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "query shorthand collision",
			caddyfile: `map {path} {http.request.uri.query.q} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "re shorthand collision",
			caddyfile: `map {path} {http.regexp.name.1} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "vars shorthand collision",
			caddyfile: `map {path} {http.vars.myvar} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "rp shorthand collision",
			caddyfile: `map {path} {http.reverse_proxy.upstream} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "resp shorthand collision",
			caddyfile: `map {path} {http.intercept.status} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "err shorthand collision",
			caddyfile: `map {path} {http.error.status_code} {
				/foo bar
			}`,
			wantErr: true,
		},
		{
			name: "file_match shorthand collision",
			caddyfile: `map {path} {http.matchers.file.base} {
				/foo bar
			}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			disp := caddyfile.NewTestDispenser(tc.caddyfile)
			helper := httpcaddyfile.Helper{Dispenser: disp}
			_, err := parseCaddyfile(helper)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s, got none", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}
