package httpcaddyfile

import (
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type ComplexShorthandReplacer struct {
	search         *regexp.Regexp
	replace        string
	inverse        *regexp.Regexp
	inverseReplace string
}

type ShorthandReplacer struct {
	complex []ComplexShorthandReplacer
	simple  *strings.Replacer
}

func NewShorthandReplacer() ShorthandReplacer {
	// replace shorthand placeholders (which are convenient
	// when writing a Caddyfile) with their actual placeholder
	// identifiers or variable names
	replacer := strings.NewReplacer(placeholderShorthands()...)

	// these are placeholders that allow a user-defined final
	// parameters, but we still want to provide a shorthand
	// for those, so we use a regexp to replace
	regexpReplacements := []ComplexShorthandReplacer{
		{
			search:         regexp.MustCompile(`{header\.([\w-]*)}`),
			replace:        "{http.request.header.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.header\.([\w-]*)\}$`),
			inverseReplace: "{header.$1}",
		},
		{
			search:         regexp.MustCompile(`{cookie\.([\w-]*)}`),
			replace:        "{http.request.cookie.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.cookie\.([\w-]*)\}$`),
			inverseReplace: "{cookie.$1}",
		},
		{
			search:         regexp.MustCompile(`{labels\.([\w-]*)}`),
			replace:        "{http.request.host.labels.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.host\.labels\.([\w-]*)\}$`),
			inverseReplace: "{labels.$1}",
		},
		{
			search:         regexp.MustCompile(`{path\.([\w-]*)}`),
			replace:        "{http.request.uri.path.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.uri\.path\.([\w-]*)\}$`),
			inverseReplace: "{path.$1}",
		},
		{
			search:         regexp.MustCompile(`{file\.([\w-]*)}`),
			replace:        "{http.request.uri.path.file.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.uri\.path\.file\.([\w-]*)\}$`),
			inverseReplace: "{file.$1}",
		},
		{
			search:         regexp.MustCompile(`{query\.([\w-]*)}`),
			replace:        "{http.request.uri.query.$1}",
			inverse:        regexp.MustCompile(`^\{http\.request\.uri\.query\.([\w-]*)\}$`),
			inverseReplace: "{query.$1}",
		},
		{
			search:         regexp.MustCompile(`{re\.([\w-\.]*)}`),
			replace:        "{http.regexp.$1}",
			inverse:        regexp.MustCompile(`^\{http\.regexp\.([\w-\.]*)\}$`),
			inverseReplace: "{re.$1}",
		},
		{
			search:         regexp.MustCompile(`{vars\.([\w-]*)}`),
			replace:        "{http.vars.$1}",
			inverse:        regexp.MustCompile(`^\{http\.vars\.([\w-]*)\}$`),
			inverseReplace: "{vars.$1}",
		},
		{
			search:         regexp.MustCompile(`{rp\.([\w-\.]*)}`),
			replace:        "{http.reverse_proxy.$1}",
			inverse:        regexp.MustCompile(`^\{http\.reverse_proxy\.([\w-\.]*)\}$`),
			inverseReplace: "{rp.$1}",
		},
		{
			search:         regexp.MustCompile(`{resp\.([\w-\.]*)}`),
			replace:        "{http.intercept.$1}",
			inverse:        regexp.MustCompile(`^\{http\.intercept\.([\w-\.]*)\}$`),
			inverseReplace: "{resp.$1}",
		},
		{
			search:         regexp.MustCompile(`{err\.([\w-\.]*)}`),
			replace:        "{http.error.$1}",
			inverse:        regexp.MustCompile(`^\{http\.error\.([\w-\.]*)\}$`),
			inverseReplace: "{err.$1}",
		},
		{
			search:         regexp.MustCompile(`{file_match\.([\w-]*)}`),
			replace:        "{http.matchers.file.$1}",
			inverse:        regexp.MustCompile(`^\{http\.matchers\.file\.([\w-]*)\}$`),
			inverseReplace: "{file_match.$1}",
		},
	}

	return ShorthandReplacer{
		complex: regexpReplacements,
		simple:  replacer,
	}
}

// placeholderShorthands returns a slice of old-new string pairs,
// where the left of the pair is a placeholder shorthand that may
// be used in the Caddyfile, and the right is the replacement.
func placeholderShorthands() []string {
	return []string{
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{orig_method}", "{http.request.orig_method}",
		"{orig_uri}", "{http.request.orig_uri}",
		"{orig_path}", "{http.request.orig_uri.path}",
		"{orig_dir}", "{http.request.orig_uri.path.dir}",
		"{orig_file}", "{http.request.orig_uri.path.file}",
		"{orig_query}", "{http.request.orig_uri.query}",
		"{orig_?query}", "{http.request.orig_uri.prefixed_query}",
		"{method}", "{http.request.method}",
		"{uri}", "{http.request.uri}",
		"{%uri}", "{http.request.uri_escaped}",
		"{path}", "{http.request.uri.path}",
		"{%path}", "{http.request.uri.path_escaped}",
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{query}", "{http.request.uri.query}",
		"{%query}", "{http.request.uri.query_escaped}",
		"{?query}", "{http.request.uri.prefixed_query}",
		"{remote}", "{http.request.remote}",
		"{remote_host}", "{http.request.remote.host}",
		"{remote_port}", "{http.request.remote.port}",
		"{scheme}", "{http.request.scheme}",
		"{uuid}", "{http.request.uuid}",
		"{tls_cipher}", "{http.request.tls.cipher_suite}",
		"{tls_version}", "{http.request.tls.version}",
		"{tls_client_fingerprint}", "{http.request.tls.client.fingerprint}",
		"{tls_client_issuer}", "{http.request.tls.client.issuer}",
		"{tls_client_serial}", "{http.request.tls.client.serial}",
		"{tls_client_subject}", "{http.request.tls.client.subject}",
		"{tls_client_certificate_pem}", "{http.request.tls.client.certificate_pem}",
		"{tls_client_certificate_der_base64}", "{http.request.tls.client.certificate_der_base64}",
		"{upstream_hostport}", "{http.reverse_proxy.upstream.hostport}",
		"{client_ip}", "{http.vars.client_ip}",
	}
}

// ApplyToSegment replaces shorthand placeholder to its full placeholder, understandable by Caddy.
func (s ShorthandReplacer) ApplyToSegment(segment *caddyfile.Segment) {
	if segment != nil {
		for i := 0; i < len(*segment); i++ {
			// simple string replacements
			(*segment)[i].Text = s.simple.Replace((*segment)[i].Text)
			// complex regexp replacements
			for _, r := range s.complex {
				(*segment)[i].Text = r.search.ReplaceAllString((*segment)[i].Text, r.replace)
			}
		}
	}
}
