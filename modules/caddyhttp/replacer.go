// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// NewTestReplacer creates a replacer for an http.Request
// for use in tests that are not in this package
func NewTestReplacer(req *http.Request) *caddy.Replacer {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	*req = *req.WithContext(ctx)
	addHTTPVarsToReplacer(repl, req, nil)
	return repl
}

func addHTTPVarsToReplacer(repl *caddy.Replacer, req *http.Request, w http.ResponseWriter) {
	SetVar(req.Context(), "start_time", time.Now())
	SetVar(req.Context(), "uuid", new(requestID))

	// Request-scoped memoization cache for replacer placeholders
	var (
		reqHostVal    any
		reqPortVal    any
		reqHostLabels []any
		reqHostSplit  bool

		localHostVal   any
		localPortVal   any
		localAddrSplit bool

		remoteHostVal   any
		remoteHostStr   string
		remotePortVal   any
		remoteAddrSplit bool

		remotePrefixCache map[string]any

		prefixedQueryVal     any
		prefixedQuerySet     bool
		origPrefixedQueryVal any
		origPrefixedQuerySet bool
	)

	splitReqHost := func() {
		reqHostSplit = true
		host, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			reqHostVal = req.Host
			reqPortVal = ""
			rawLabels := strings.Split(req.Host, ".")
			reqHostLabels = make([]any, len(rawLabels))
			for i, l := range rawLabels {
				reqHostLabels[i] = strings.ToLower(l)
			}
		} else {
			reqHostVal = host
			if portNum, err := strconv.Atoi(port); err == nil {
				reqPortVal = portNum
			} else {
				reqPortVal = port
			}
			rawLabels := strings.Split(host, ".")
			reqHostLabels = make([]any, len(rawLabels))
			for i, l := range rawLabels {
				reqHostLabels[i] = strings.ToLower(l)
			}
		}
	}

	splitLocalAddr := func() {
		localAddrSplit = true
		localAddr, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if localAddr == nil {
			localHostVal = nil
			localPortVal = nil
			return
		}
		host, port, err := net.SplitHostPort(localAddr.String())
		if err != nil {
			// localAddr is host:port for tcp and udp sockets and /unix/socket.path
			// for unix sockets. net.SplitHostPort only operates on tcp and udp sockets,
			// not unix sockets and will fail with the latter.
			// We assume when net.SplitHostPort fails, localAddr is a unix socket and thus
			// already "split" and save to return.
			localHostVal = localAddr
			localPortVal = ""
		} else {
			localHostVal = host
			if portNum, err := strconv.Atoi(port); err == nil {
				localPortVal = portNum
			} else {
				localPortVal = port
			}
		}
	}

	splitRemoteAddr := func() {
		remoteAddrSplit = true
		host, port, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			// req.RemoteAddr is host:port for tcp and udp sockets and /unix/socket.path
			// for unix sockets. net.SplitHostPort only operates on tcp and udp sockets,
			// not unix sockets and will fail with the latter.
			// We assume when net.SplitHostPort fails, req.RemoteAddr is a unix socket
			// and thus already "split" and save to return.
			remoteHostVal = req.RemoteAddr
			remoteHostStr = req.RemoteAddr
			remotePortVal = ""
		} else {
			remoteHostVal = host
			remoteHostStr = host
			if portNum, err := strconv.Atoi(port); err == nil {
				remotePortVal = portNum
			} else {
				remotePortVal = port
			}
		}
	}

	httpVars := func(key string) (any, bool) {
		if req != nil {
			// query string parameters
			if strings.HasPrefix(key, reqURIQueryReplPrefix) {
				vals := req.URL.Query()[key[len(reqURIQueryReplPrefix):]]
				// always return true, since the query param might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			// request header fields
			if strings.HasPrefix(key, reqHeaderReplPrefix) {
				field := key[len(reqHeaderReplPrefix):]
				vals := req.Header[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			// cookies
			if strings.HasPrefix(key, reqCookieReplPrefix) {
				name := key[len(reqCookieReplPrefix):]
				for _, cookie := range req.Cookies() {
					if strings.EqualFold(name, cookie.Name) {
						// always return true, since the cookie might
						// be present only in some requests
						return cookie.Value, true
					}
				}
			}

			// http.request.tls.*
			if strings.HasPrefix(key, reqTLSReplPrefix) {
				return getReqTLSReplacement(req, key)
			}

			switch key {
			case "http.request.method":
				return req.Method, true
			case "http.request.scheme":
				if req.TLS != nil {
					return "https", true
				}
				return "http", true
			case "http.request.proto":
				return req.Proto, true
			case "http.request.proto_name":
				if req.ProtoMajor == 2 {
					return "HTTP/2", true
				}
				if req.ProtoMajor == 3 {
					return "HTTP/3", true
				}
				return req.Proto, true
			case "http.request.host":
				if !reqHostSplit {
					splitReqHost()
				}
				return reqHostVal, true
			case "http.request.port":
				if !reqHostSplit {
					splitReqHost()
				}
				return reqPortVal, true
			case "http.request.hostport":
				return req.Host, true
			case "http.request.local":
				localAddr, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
				if localAddr == nil {
					return nil, true
				}
				return localAddr.String(), true
			case "http.request.local.host":
				if !localAddrSplit {
					splitLocalAddr()
				}
				return localHostVal, true
			case "http.request.local.port":
				if !localAddrSplit {
					splitLocalAddr()
				}
				return localPortVal, true
			case "http.request.remote":
				if req.TLS != nil && !req.TLS.HandshakeComplete {
					// without a complete handshake (QUIC "early data") we can't trust the remote IP address to not be spoofed
					return nil, true
				}
				return req.RemoteAddr, true
			case "http.request.remote.host":
				if req.TLS != nil && !req.TLS.HandshakeComplete {
					// without a complete handshake (QUIC "early data") we can't trust the remote IP address to not be spoofed
					return nil, true
				}
				if !remoteAddrSplit {
					splitRemoteAddr()
				}
				return remoteHostVal, true
			case "http.request.remote.port":
				if !remoteAddrSplit {
					splitRemoteAddr()
				}
				return remotePortVal, true

			// current URI, including any internal rewrites
			case "http.request.uri":
				return req.URL.RequestURI(), true
			case "http.request.uri_escaped":
				return url.QueryEscape(req.URL.RequestURI()), true
			case "http.request.uri.path":
				return req.URL.Path, true
			case "http.request.uri.path_escaped":
				return url.QueryEscape(req.URL.Path), true
			case "http.request.uri.path.file":
				_, file := path.Split(req.URL.Path)
				return file, true
			case "http.request.uri.path.dir":
				dir, _ := path.Split(req.URL.Path)
				return dir, true
			case "http.request.uri.path.file.base":
				return strings.TrimSuffix(path.Base(req.URL.Path), path.Ext(req.URL.Path)), true
			case "http.request.uri.path.file.ext":
				return path.Ext(req.URL.Path), true
			case "http.request.uri.query":
				return req.URL.RawQuery, true
			case "http.request.uri.query_escaped":
				return url.QueryEscape(req.URL.RawQuery), true
			case "http.request.uri.prefixed_query":
				if !prefixedQuerySet {
					if req.URL.RawQuery != "" {
						prefixedQueryVal = "?" + req.URL.RawQuery
					}
					prefixedQuerySet = true
				}
				return prefixedQueryVal, true
			case "http.request.duration":
				start := GetVar(req.Context(), "start_time").(time.Time)
				return time.Since(start), true
			case "http.request.duration_ms":
				start := GetVar(req.Context(), "start_time").(time.Time)
				return time.Since(start).Seconds() * 1e3, true // multiply seconds to preserve decimal (see #4666)

			case "http.request.uuid":
				// fetch the UUID for this request
				id := GetVar(req.Context(), "uuid").(*requestID)

				// set it to this request's access log
				extra := req.Context().Value(ExtraLogFieldsCtxKey).(*ExtraLogFields)
				extra.Set(zap.String("uuid", id.String()))

				return id.String(), true

			case "http.request.body":
				if req.Body == nil {
					return "", true
				}
				// normally net/http will close the body for us, but since we
				// are replacing it with a fake one, we have to ensure we close
				// the real body ourselves when we're done
				defer req.Body.Close()
				// read the request body into a buffer (can't pool because we
				// don't know its lifetime and would have to make a copy anyway)
				buf := new(bytes.Buffer)
				_, _ = io.Copy(buf, req.Body) // can't handle error, so just ignore it
				req.Body = io.NopCloser(buf)  // replace real body with buffered data
				return buf.String(), true

			case "http.request.body_base64":
				if req.Body == nil {
					return "", true
				}
				// normally net/http will close the body for us, but since we
				// are replacing it with a fake one, we have to ensure we close
				// the real body ourselves when we're done
				defer req.Body.Close()
				// read the request body into a buffer (can't pool because we
				// don't know its lifetime and would have to make a copy anyway)
				buf := new(bytes.Buffer)
				_, _ = io.Copy(buf, req.Body) // can't handle error, so just ignore it
				req.Body = io.NopCloser(buf)  // replace real body with buffered data
				return base64.StdEncoding.EncodeToString(buf.Bytes()), true

			// original request, before any internal changes
			case "http.request.orig_method":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.Method, true
			case "http.request.orig_uri":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.RequestURI, true
			case "http.request.orig_uri.path":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.URL.Path, true
			case "http.request.orig_uri.path.file":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				_, file := path.Split(or.URL.Path)
				return file, true
			case "http.request.orig_uri.path.dir":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				dir, _ := path.Split(or.URL.Path)
				return dir, true
			case "http.request.orig_uri.query":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.URL.RawQuery, true
			case "http.request.orig_uri.prefixed_query":
				if !origPrefixedQuerySet {
					or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
					if or.URL.RawQuery != "" {
						origPrefixedQueryVal = "?" + or.URL.RawQuery
					}
					origPrefixedQuerySet = true
				}
				return origPrefixedQueryVal, true
			}

			// remote IP range/prefix (e.g. keep top 24 bits of 1.2.3.4  => "1.2.3.0/24")
			// syntax: "/V4,V6" where V4 = IPv4 bits, and V6 = IPv6 bits; if no comma, then same bit length used for both
			// (EXPERIMENTAL)
			if strings.HasPrefix(key, "http.request.remote.host/") {
				if val, ok := remotePrefixCache[key]; ok {
					return val, true
				}
				if !remoteAddrSplit {
					splitRemoteAddr()
				}
				if remotePrefixCache == nil {
					remotePrefixCache = make(map[string]any)
				}
				addr, err := netip.ParseAddr(remoteHostStr)
				if err != nil {
					remotePrefixCache[key] = remoteHostStr
					return remoteHostStr, true // not an IP address
				}
				// extract the bits from the end of the placeholder (start after "/") then split on ","
				bitsBoth := key[strings.Index(key, "/")+1:]
				ipv4BitsStr, ipv6BitsStr, cutOK := strings.Cut(bitsBoth, ",")
				bitsStr := ipv4BitsStr
				if addr.Is6() && cutOK {
					bitsStr = ipv6BitsStr
				}
				// convert to integer then compute prefix
				bits, err := strconv.Atoi(bitsStr)
				if err != nil {
					remotePrefixCache[key] = ""
					return "", true
				}
				prefix, err := addr.Prefix(bits)
				if err != nil {
					remotePrefixCache[key] = ""
					return "", true
				}
				prefixStr := prefix.String()
				remotePrefixCache[key] = prefixStr
				return prefixStr, true
			}

			// hostname labels (case insensitive, so normalize to lowercase)
			if strings.HasPrefix(key, reqHostLabelsReplPrefix) {
				idxStr := key[len(reqHostLabelsReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 0 {
					return "", false
				}
				if !reqHostSplit {
					splitReqHost()
				}
				if idx >= len(reqHostLabels) {
					return "", true
				}
				return reqHostLabels[len(reqHostLabels)-idx-1], true
			}

			// path parts
			if strings.HasPrefix(key, reqURIPathReplPrefix) {
				idxStr := key[len(reqURIPathReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return "", false
				}
				pathParts := strings.Split(req.URL.Path, "/")
				if len(pathParts) > 0 && pathParts[0] == "" {
					pathParts = pathParts[1:]
				}
				if idx < 0 {
					return "", false
				}
				if idx >= len(pathParts) {
					return "", true
				}
				return pathParts[idx], true
			}

			// orig uri path parts
			if strings.HasPrefix(key, reqOrigURIPathReplPrefix) {
				idxStr := key[len(reqOrigURIPathReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return "", false
				}
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				pathParts := strings.Split(or.URL.Path, "/")
				if len(pathParts) > 0 && pathParts[0] == "" {
					pathParts = pathParts[1:]
				}
				if idx < 0 {
					return "", false
				}
				if idx >= len(pathParts) {
					return "", true
				}
				return pathParts[idx], true
			}

			// middleware variables
			if strings.HasPrefix(key, varsReplPrefix) {
				varName := key[len(varsReplPrefix):]
				raw := GetVar(req.Context(), varName)
				// variables can be dynamic, so always return true
				// even when it may not be set; treat as empty then
				return raw, true
			}
		}

		if w != nil {
			// response header fields
			if strings.HasPrefix(key, respHeaderReplPrefix) {
				field := key[len(respHeaderReplPrefix):]
				vals := w.Header()[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some responses
				return strings.Join(vals, ","), true
			}
		}

		switch key {
		case "http.shutting_down":
			server := req.Context().Value(ServerCtxKey).(*Server)
			return server.shutdownAt.Load() != nil, true
		case "http.time_until_shutdown":
			server := req.Context().Value(ServerCtxKey).(*Server)
			t := server.shutdownAt.Load()
			if t == nil {
				return nil, true
			}
			return time.Until(*t), true
		}

		return nil, false
	}

	repl.Map(httpVars)
}

func getReqTLSReplacement(req *http.Request, key string) (any, bool) {
	if req == nil || req.TLS == nil {
		return nil, false
	}

	if len(key) < len(reqTLSReplPrefix) {
		return nil, false
	}

	field := strings.ToLower(key[len(reqTLSReplPrefix):])

	if strings.HasPrefix(field, "client.") {
		cert := getTLSPeerCert(req.TLS)
		if cert == nil {
			// Instead of returning (nil, false) here, we set it to a dummy
			// value to fix #7530. This way, even if there is no client cert,
			// evaluating placeholders with ReplaceKnown() will still remove
			// the placeholder, which would be expected. It is not expected
			// for the placeholder to sometimes get removed based on whether
			// the client presented a cert. We also do not return true here
			// because we probably should remain accurate about whether a
			// placeholder is, in fact, known or not.
			// (This allocation may be slightly inefficient.)
			cert = new(x509.Certificate)
		}

		// subject alternate names (SANs)
		if strings.HasPrefix(field, "client.san.") {
			field = field[len("client.san."):]
			var fieldName string
			var fieldValue any
			switch {
			case strings.HasPrefix(field, "dns_names"):
				fieldName = "dns_names"
				fieldValue = cert.DNSNames
			case strings.HasPrefix(field, "emails"):
				fieldName = "emails"
				fieldValue = cert.EmailAddresses
			case strings.HasPrefix(field, "ips"):
				fieldName = "ips"
				fieldValue = cert.IPAddresses
			case strings.HasPrefix(field, "uris"):
				fieldName = "uris"
				fieldValue = cert.URIs
			default:
				return nil, false
			}
			field = field[len(fieldName):]

			// if no index was specified, return the whole list
			if field == "" {
				return fieldValue, true
			}
			if len(field) < 2 || field[0] != '.' {
				return nil, false
			}
			field = field[1:] // trim '.' between field name and index

			// get the numeric index
			idx, err := strconv.Atoi(field)
			if err != nil || idx < 0 {
				return nil, false
			}

			// access the indexed element and return it
			switch v := fieldValue.(type) {
			case []string:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []net.IP:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []*url.URL:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			}
		}

		switch field {
		case "client.fingerprint":
			return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), true
		case "client.public_key", "client.public_key_sha256":
			if cert.PublicKey == nil {
				return nil, true
			}
			pubKeyBytes, err := marshalPublicKey(cert.PublicKey)
			if err != nil {
				return nil, true
			}
			if strings.HasSuffix(field, "_sha256") {
				return fmt.Sprintf("%x", sha256.Sum256(pubKeyBytes)), true
			}
			return fmt.Sprintf("%x", pubKeyBytes), true
		case "client.issuer":
			return cert.Issuer, true
		case "client.serial":
			return cert.SerialNumber, true
		case "client.subject":
			return cert.Subject, true
		case "client.certificate_pem":
			block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			return pem.EncodeToMemory(&block), true
		case "client.certificate_der_base64":
			return base64.StdEncoding.EncodeToString(cert.Raw), true
		default:
			return nil, false
		}
	}

	switch field {
	case "version":
		return caddytls.ProtocolName(req.TLS.Version), true
	case "cipher_suite":
		return tls.CipherSuiteName(req.TLS.CipherSuite), true
	case "resumed":
		return req.TLS.DidResume, true
	case "proto":
		return req.TLS.NegotiatedProtocol, true
	case "proto_mutual":
		// req.TLS.NegotiatedProtocolIsMutual is deprecated - it's always true.
		return true, true
	case "server_name":
		return req.TLS.ServerName, true
	case "ech":
		return req.TLS.ECHAccepted, true
	}
	return nil, false
}

// marshalPublicKey returns the byte encoding of pubKey.
func marshalPublicKey(pubKey any) ([]byte, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return asn1.Marshal(key)
	case *ecdsa.PublicKey:
		e, err := key.ECDH()
		if err != nil {
			return nil, err
		}
		return e.Bytes(), nil
	case ed25519.PublicKey:
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized public key type: %T", pubKey)
}

// getTLSPeerCert retrieves the first peer certificate from a TLS session.
// Returns nil if no peer cert is in use.
func getTLSPeerCert(cs *tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

type requestID struct {
	value string
}

// Lazy generates UUID string or return cached value if present
func (rid *requestID) String() string {
	if rid.value == "" {
		if id, err := uuid.NewRandom(); err == nil {
			rid.value = id.String()
		}
	}
	return rid.value
}

const (
	reqCookieReplPrefix      = "http.request.cookie."
	reqHeaderReplPrefix      = "http.request.header."
	reqHostLabelsReplPrefix  = "http.request.host.labels."
	reqTLSReplPrefix         = "http.request.tls."
	reqURIPathReplPrefix     = "http.request.uri.path."
	reqURIQueryReplPrefix    = "http.request.uri.query."
	respHeaderReplPrefix     = "http.response.header."
	varsReplPrefix           = "http.vars."
	reqOrigURIPathReplPrefix = "http.request.orig_uri.path."
)
