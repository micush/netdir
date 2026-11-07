package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// What a caller that must never see a secret (an MCP caller: the assistant is a public service) may be given.  Secrets are
// found by name, so the answer to "can it leak?" is "less often", not "never": the rules below therefore also refuse
// whole classes of answer (a configuration, a text file, the parts of an API that hold users, keys and certificates).

// secretTokens: a word of a line that holds one of these, or is one of secretWords, hides the rest of the line.
var secretTokenParts = []string{"password", "passwd", "secret", "psk", "passphrase", "md5", "encrypted", "token", "key-string",
	"key_string", "auth-key", "authentication-key", "pre-shared", "privatekey", "private-key", "community-string", "pwd", "phash", "api-key", "communitystring", "authpass", "privpass", "cryptopass", "snmp_community"}
var secretTokenExact = map[string]bool{"key": true, "community": true, "ro": false}

var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE|PGP)[A-Z ]*-----.*?(-----END [^\n]*-----|$)`)
	jsonSec  = regexp.MustCompile(`(?i)("[^"]*(password|passwd|secret|psk|passphrase|token|key-string|auth-key|authentication-key|encrypted|communitystring|authpass|privpass|cryptopass|snmp_community)[^"]*"\s*[:=]\s*)("([^"\\]|\\.)*"|[^,}\s]+)`)
)

// jsonMember is one line of indented JSON that holds a member with a plain value: "key": "value",
var jsonMember = regexp.MustCompile(`^(\s*)("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false|null)(\s*,?\s*)$`)

// jsonQuote writes s as a JSON string, without escaping < > and &.
func jsonQuote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// secretWord says whether a word names a secret: one of secretTokenParts is in it, or it is one of secretTokenExact.
func secretWord(lw string) bool {
	hit := secretTokenExact[lw]
	for _, p := range secretTokenParts {
		hit = hit || strings.Contains(lw, p)
	}
	return hit
}

// redactLine hides what follows a secret word on one line of text: the rest of the line reads "(hidden)".
func redactLine(ln string) string {
	fs := strings.Fields(ln)
	for j, w := range fs {
		if !secretWord(strings.ToLower(strings.TrimRight(w, ":="))) || j == len(fs)-1 {
			continue
		}
		// keep the indentation and the words up to and including the keyword
		idx := 0
		for k := 0; k <= j; k++ {
			idx = strings.Index(ln[idx:], fs[k]) + idx + len(fs[k])
		}
		return ln[:idx] + " (hidden)"
	}
	return ln
}

// redactJSONMember does for a line of JSON what redactLine does for text, and leaves it JSON: the value of a member named like a
// secret is "(hidden)", and a text value is hidden from a secret word on, inside its quotes.  A number or a boolean is left.
func redactJSONMember(m []string) string {
	var key, val string
	if json.Unmarshal([]byte(m[2]), &key) != nil || json.Unmarshal([]byte(m[4]), &val) != nil {
		return m[0] // the value is not a string (a number, true, null): nothing to hide in it
	}
	switch {
	case val == "" || val == "(hidden)":
	case secretWord(strings.ToLower(key)):
		val = "(hidden)"
	default:
		val = redactLine(val)
	}
	return m[1] + m[2] + m[3] + jsonQuote(val) + m[5]
}

// RedactText hides the secrets in the text of a show command: after a word such as password, secret, key, community or
// md5 the rest of the line reads "(hidden)", and PEM blocks are removed.  A line of JSON ("key": "value",) is hidden inside its
// quotes, so an answer that is JSON stays JSON.  It hides more than it has to.
func RedactText(s string) string {
	s = pemBlock.ReplaceAllString(s, "(hidden: key or certificate)")
	s = jsonSec.ReplaceAllString(s, `${1}"(hidden)"`)
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if m := jsonMember.FindStringSubmatch(ln); m != nil {
			lines[i] = redactJSONMember(m)
			continue
		}
		lines[i] = redactLine(ln)
	}
	return strings.Join(lines, "\n")
}

var deniedAny = []string{"snmp", "username", "aaa", "tacacs", "radius", "crypto", "password", "secret", "certificate", "keychain", "key-chain",
	"ikev", "ipsec", "vpn", "license", "admin", "ldap", "saml", "oauth", "sso", "api-user", "central-management", "fortiguard", "wireless-controller", "switch-controller", "ssh", "pki",
	// NX-OS's object model (userext: its users), PAN-OS's configuration (management users, authentication profiles and sequences,
	// server profiles, high availability keys, the device-level settings)
	"userext", "mgt-config", "local-user-database", "authentication-profile", "authentication-sequence", "kerberos", "server-profile",
	"high-availability", "master-key", "deviceconfig",
	// ArubaOS-CX (the whole configuration is fullconfigs, running-config and startup-config), Infoblox WAPI (admin users and groups
	// are "admin*", authentication services and policies, DNSSEC and TSIG keys, file operations)
	"fullconfigs", "running-config", "startup-config", "authservice", "authpolicy", "dnsseckey", "tsig", "fileop",
	// Arista EOS (the commands a path of its eAPI names; see eosDeniedWord for the abbreviations the CLI accepts)
	"session-config", "tech-support",
	// F5 BIG-IP (TLS keys and certificates, UCS archives, file transfer, the authentication tree)
	"ssl-key", "ssl-cert", "ucs", "file-transfer", "authn", "authz",
	// Cisco Meraki (administrators are "admins", sign-in, license keys, API keys)
	"loginsecurity", "licens", "apikey"}
var deniedExact = map[string]bool{"line": true, "enable": true, "key": true, "keys": true, "user": true, "users": true, "banner": true, "authentication": true, "backup": true,
	"ike": true, "accounts": true, "auth": true, "util": true, "login": true}

// secretSegment refuses one word of a path (or of an XPath, or an element of a command) that names a place secrets are kept.
func secretSegment(sg string) error {
	if _, after, ok := strings.Cut(sg, ":"); ok { // module:container
		sg = after
	}
	if deniedExact[sg] {
		return fmt.Errorf("path: %q holds secrets (users, keys, certificates) and is not available over MCP", sg)
	}
	for _, d := range deniedAny {
		w := sg
		if d == "aaa" {
			w = strings.ReplaceAll(sg, "aaaa", "") // AAAA is the DNS record type (Infoblox record:aaaa, sharedrecord:aaaa), not AAA
		}
		if strings.Contains(w, d) {
			return fmt.Errorf("path: %q holds secrets (users, keys, certificates, SNMP, AAA) and is not available over MCP", sg)
		}
	}
	return nil
}

// CheckAPIPathMCP is CheckAPIPath for a caller that must not see secrets: the whole configuration, and the parts of the
// API that hold users, keys, certificates, SNMP and AAA, are refused.  The named tools (ports, routing, firewall, ...) read
// what they need and hide what is secret.
func CheckAPIPathMCP(p string) error {
	path, query, _ := strings.Cut(p, "?")
	path = strings.ToLower(path)
	if path == "/api" || path == "/api/" {
		return checkPanosQueryMCP(query) // PAN-OS's XML API: the path is always /api/, what is asked for is in the query
	}
	segs := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '=' })
	for i, sg := range segs {
		if _, after, ok := strings.Cut(sg, ":"); ok { // module:container
			sg = after
		}
		base := strings.TrimSuffix(strings.TrimSuffix(sg, ".json"), ".xml")
		if sg == "native" && i == len(segs)-1 || sg == "cmdb" && i == len(segs)-1 ||
			base == "sys" && i == len(segs)-1 && strings.HasPrefix(path, "/api/") { // NX-OS: sys is the root of the object model
			return errors.New("path: a whole configuration holds the device's secrets and is not available over MCP; ask for a part (the device_* tools, or a path below it)")
		}
		if err := secretSegment(sg); err != nil {
			return err
		}
	}
	if strings.HasPrefix(path, "/rpc/") { // Juniper Junos REST: the path is an RPC name
		if err := junRPCDenied(strings.TrimPrefix(path, "/rpc/")); err != nil {
			return err
		}
	}
	if strings.HasPrefix(path, "/eapi/") { // Arista eAPI: the path is a CLI command, and the CLI accepts abbreviations ("show run")
		for _, w := range strings.Split(strings.TrimPrefix(path, "/eapi/"), "/") {
			if err := eosDeniedWord(w); err != nil {
				return err
			}
		}
	}
	if strings.HasPrefix(path, "/restconf/tailf") {
		return errors.New("path: model sources are text and not available over MCP")
	}
	return nil
}

// xpathSteps are the element names of an XPath, without their predicates; a "/" inside [...] or quotes does not split
// (entry[@name='ethernet1/1']).  A step's parent is the step before it.
func xpathSteps(x string) (names []string, preds []bool) {
	depth, quote := 0, byte(0)
	start := 0
	flush := func(end int) {
		if s := x[start:end]; s != "" {
			name, _, hasPred := strings.Cut(s, "[")
			names, preds = append(names, strings.ToLower(strings.TrimSpace(name))), append(preds, hasPred)
		}
	}
	for i := 0; i < len(x); i++ {
		c := x[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '[':
			depth++
		case c == ']':
			if depth > 0 {
				depth--
			}
		case c == '/' && depth == 0:
			flush(i)
			start = i + 1
		}
	}
	flush(len(x))
	return names, preds
}

// panWholeConfig are the containers of PAN-OS's configuration tree that hold the rest of it: asking for one (or for one of
// their entries) is asking for the whole configuration, secrets included.
var panWholeConfig = map[string]bool{"config": true, "devices": true, "shared": true, "vsys": true, "device-group": true, "template": true,
	"template-stack": true, "panorama": true, "localhost.localdomain": true}

// checkPanosQueryMCP applies the same rules to a PAN-OS XML API request: a show command or an XPath is read, never the whole
// configuration, never a place secrets are kept, and never the "show config" family (which prints the configuration).
func checkPanosQueryMCP(query string) error {
	q, err := url.ParseQuery(query)
	if err != nil {
		return fmt.Errorf("path: the query: %v", err)
	}
	switch q.Get("type") {
	case "op":
		names, err := panShowNames(q.Get("cmd"))
		if err != nil {
			return err
		}
		for _, n := range names {
			n = strings.ToLower(n)
			if n == "config" {
				return errors.New(`path: "show config" prints the configuration, which holds secrets, and is not available over MCP`)
			}
			if err := secretSegment(n); err != nil {
				return err
			}
		}
	case "config":
		names, preds := xpathSteps(q.Get("xpath"))
		if len(names) == 0 {
			return errors.New("path: an xpath is needed (not the whole configuration over MCP)")
		}
		last := len(names) - 1
		if panWholeConfig[names[last]] || names[last] == "entry" && last > 0 && preds[last] && panWholeConfig[names[last-1]] {
			return errors.New("path: a whole configuration holds the device's secrets and is not available over MCP; ask for a part (the device_* tools, or an xpath below it)")
		}
		for _, n := range names {
			if err := secretSegment(n); err != nil {
				return err
			}
		}
	default:
		return errors.New("path: over MCP the XML API reads type=op (a show command) or type=config (a part of the configuration)")
	}
	return nil
}

// eosDeniedWords are the commands of the EOS CLI that print secrets or the whole configuration.
var eosDeniedWords = []string{"running-config", "startup-config", "session-config", "tech-support", "snmp", "users", "aaa", "radius", "tacacs", "crypto", "kerberos", "certificate", "secret", "privilege"}

// eosDeniedWord refuses a word of an eAPI command that is, or abbreviates, one of eosDeniedWords: the CLI takes any unique prefix
// ("show run" is "show running-config"), which a match on the whole word would let through.  A word of one letter is not taken
// for an abbreviation.
func eosDeniedWord(w string) error {
	w = strings.ToLower(strings.TrimSpace(w))
	if u, err := url.PathUnescape(w); err == nil {
		w = u
	}
	if len(w) < 2 {
		return nil
	}
	for _, d := range eosDeniedWords {
		if strings.HasPrefix(d, w) {
			return fmt.Errorf("path: %q holds secrets or the whole configuration and is not available over MCP", w)
		}
	}
	return nil
}
