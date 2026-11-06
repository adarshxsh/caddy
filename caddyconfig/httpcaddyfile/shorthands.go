package httpcaddyfile

import (
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type complexShorthand struct {
	forwardSearch     *regexp.Regexp
	forwardReplace    string
	inverseSearch     *regexp.Regexp
	shorthandTemplate string
}

var complexShorthands = []complexShorthand{
	{
		forwardSearch:     regexp.MustCompile(`{header\.([\w-]*)}`),
		forwardReplace:    "{http.request.header.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.header\.([\w-]*)$`),
		shorthandTemplate: "{header.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{cookie\.([\w-]*)}`),
		forwardReplace:    "{http.request.cookie.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.cookie\.([\w-]*)$`),
		shorthandTemplate: "{cookie.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{labels\.([\w-]*)}`),
		forwardReplace:    "{http.request.host.labels.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.host\.labels\.([\w-]*)$`),
		shorthandTemplate: "{labels.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{file\.([\w-]*)}`),
		forwardReplace:    "{http.request.uri.path.file.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.uri\.path\.file\.([\w-]*)$`),
		shorthandTemplate: "{file.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{path\.([\w-]*)}`),
		forwardReplace:    "{http.request.uri.path.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.uri\.path\.([\w-]*)$`),
		shorthandTemplate: "{path.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{query\.([\w-]*)}`),
		forwardReplace:    "{http.request.uri.query.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.request\.uri\.query\.([\w-]*)$`),
		shorthandTemplate: "{query.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{re\.([\w-\.]*)}`),
		forwardReplace:    "{http.regexp.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.regexp\.([\w-\.]*)$`),
		shorthandTemplate: "{re.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{vars\.([\w-]*)}`),
		forwardReplace:    "{http.vars.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.vars\.([\w-]*)$`),
		shorthandTemplate: "{vars.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{rp\.([\w-\.]*)}`),
		forwardReplace:    "{http.reverse_proxy.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.reverse_proxy\.([\w-\.]*)$`),
		shorthandTemplate: "{rp.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{resp\.([\w-\.]*)}`),
		forwardReplace:    "{http.intercept.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.intercept\.([\w-\.]*)$`),
		shorthandTemplate: "{resp.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{err\.([\w-\.]*)}`),
		forwardReplace:    "{http.error.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.error\.([\w-\.]*)$`),
		shorthandTemplate: "{err.$1}",
	},
	{
		forwardSearch:     regexp.MustCompile(`{file_match\.([\w-]*)}`),
		forwardReplace:    "{http.matchers.file.$1}",
		inverseSearch:     regexp.MustCompile(`^http\.matchers\.file\.([\w-]*)$`),
		shorthandTemplate: "{file_match.$1}",
	},
}

type ShorthandReplacer struct {
	complex []complexShorthand
	simple  *strings.Replacer
}

func NewShorthandReplacer() ShorthandReplacer {
	return ShorthandReplacer{
		complex: complexShorthands,
		simple:  strings.NewReplacer(placeholderShorthands()...),
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
				(*segment)[i].Text = r.forwardSearch.ReplaceAllString((*segment)[i].Text, r.forwardReplace)
			}
		}
	}
}
