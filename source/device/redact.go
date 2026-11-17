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
	"key_string", "auth-key", "authentication-key", "pre-shared", "privatekey", "private-key", "community-string", "pwd", "phash", "api-key", "communitystring", "authpass", "privpass", "cryptopass", "snmp_community",
	"passkey", "pass_key", "auth_pass", "priv_pass", "authentication_key", "keepalive_key", "ciphertext", "keystring", "shared_key", "shared-key", "sharedkey"}
var secretTokenExact = map[string]bool{"key": true, "community": true, "ro": false}

var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE|PGP)[A-Z ]*-----.*?(-----END [^\n]*-----|$)`)
	jsonSec  = regexp.MustCompile(`(?i)("[^"]*(password|passwd|secret|psk|passphrase|token|key-string|auth-key|authentication-key|encrypted|communitystring|authpass|privpass|cryptopass|snmp_community|passkey|pass_key|auth_pass|priv_pass|authentication_key|keepalive_key|ciphertext|keystring|shared_key|sharedkey)[^"]*"\s*[:=]\s*)("([^"\\]|\\.)*"|[^,}\s{\[][^,}\s]*)`)
)

// jsonMember is one line of indented JSON that holds a member with a plain value: "key": "value",
var jsonMember = regexp.MustCompile(`^(\s*)("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false|null)(\s*,?\s*)$`)

// jsonElem is one line of indented JSON that is a text in a list: "value",
var jsonElem = regexp.MustCompile(`^(\s*)("(?:[^"\\]|\\.)*")(\s*,?\s*)$`)
var sshKey = regexp.MustCompile(`^(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) `)

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
	hit := secretTokenExact[lw] || holdsExtra(lw)
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
	case val == "" || val == "(hidden)" || strings.Contains(val, "(hidden"): // already hidden (a PEM block, a secret named by the line above)
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
	if Unfiltered() {
		return s
	}
	s = pemBlock.ReplaceAllString(s, "(hidden: key or certificate)")
	s = jsonSec.ReplaceAllString(s, `${1}"(hidden)"`)
	if re := secretExtras().re; re != nil {
		s = re.ReplaceAllString(s, `${1}"(hidden)"`)
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		// the line that opens an object or a list ("SNMP_Community": {) holds no value: its members are looked at one by one, and cutting it would break the JSON
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, `"`) && (strings.HasSuffix(t, "{") || strings.HasSuffix(t, "[")) {
			continue
		}
		if m := jsonElem.FindStringSubmatch(ln); m != nil { // a text in a list: hidden whole when it holds a secret word or is a public key
			var val string
			if json.Unmarshal([]byte(m[2]), &val) == nil && (redactLine(val) != val || sshKey.MatchString(val)) {
				lines[i] = m[1] + `"(hidden)"` + m[3]
			}
			continue
		}
		if m := jsonMember.FindStringSubmatch(ln); m != nil {
			lines[i] = redactJSONMember(m)
			continue
		}
		lines[i] = redactLine(ln)
	}
	return strings.Join(lines, "\n")
}

// CheckAPIPathMCPFor is CheckAPIPathMCP for the platform of the device that is asked.
func CheckAPIPathMCPFor(platform, p string) error { return CheckAPIPathMCP(p) }

// CheckAPIPathMCP checks that a path an MCP caller reads is a read of the device's API, in the form the device takes.  It does not
// refuse a place for the words in it (vpn, users, snmp, keys...): what a device answers is filtered for secrets (Redact, RedactText,
// and the words of Configure ▸ Privacy ▸ Secret words) whatever path it came from, so a path is no secret.
func CheckAPIPathMCP(p string) error {
	path, query, _ := strings.Cut(p, "?")
	path = strings.ToLower(path)
	if path == "/api" || path == "/api/" {
		return checkPanosQueryMCP(query) // PAN-OS's XML API: the path is always /api/, what is asked for is in the query
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

// checkPanosQueryMCP checks a PAN-OS XML API request: one <show> command, an XPath, or a search of the logs.  What they answer is
// filtered for secrets like every other answer.
func checkPanosQueryMCP(query string) error {
	q, err := url.ParseQuery(query)
	if err != nil {
		return fmt.Errorf("path: the query: %v", err)
	}
	switch q.Get("type") {
	case "op":
		if _, err := panShowNames(q.Get("cmd")); err != nil {
			return err
		}
	case "config":
		if names, _ := xpathSteps(q.Get("xpath")); len(names) == 0 {
			return errors.New("path: an xpath is needed")
		}
	case "log":
		if lt := q.Get("log-type"); !PanLogTypeOK(lt) {
			return errors.New("path: type=log needs a log-type (traffic, threat, url, system, globalprotect, userid, auth, ...)")
		}
		for k := range q {
			if k == "action" || k == "job-id" {
				return errors.New("path: a log search is one request here (log-type, query, nlogs, skip, dir): the job is handled for you")
			}
		}
	default:
		return errors.New("path: over MCP the XML API reads type=op (a show command), type=config (a part of the configuration) or type=log (a search of the logs)")
	}
	return nil
}

// RedactConfig hides the secrets in a device's whole configuration for a caller who is not to see them (an MCP caller).
// A configuration that is JSON is filtered by the names of its keys (Redact) and written again indented, then every line
// goes through RedactText, as the text of a show command does; any other text goes through RedactText alone.  It is safe to
// apply twice, so an answer relayed from a gateway below is filtered again here.  The words are the shared ones (secretWords
// and Configure ▸ Privacy ▸ Secret words).
func RedactConfig(s string) string {
	if Unfiltered() {
		return s
	}
	var v any
	if json.Unmarshal([]byte(s), &v) == nil {
		switch v.(type) {
		case map[string]any, []any:
			if b, err := json.MarshalIndent(Redact(v), "", "  "); err == nil {
				s = string(b)
			}
		}
	}
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "<") {
		return redactXML(s)
	}
	return RedactText(redactCLI(s))
}

var (
	xmlElem = regexp.MustCompile(`<([A-Za-z_][\w.:-]*)((?:\s[^<>]*)?)>([^<>]+)</([A-Za-z_][\w.:-]*)>`)
	xmlAttr = regexp.MustCompile(`(?i)(\s[\w:.-]+=)"([^"]*)"`)
)

// redactXML hides the text of every element, and the value of every attribute, whose name is a secret's (PAN-OS: phash, key,
// secret, snmp-community-string, private-key, ...), and PEM blocks, leaving the rest of the XML as it was, in one line or many.
func redactXML(s string) string {
	s = pemBlock.ReplaceAllString(s, "(hidden: key or certificate)")
	hideName := func(n string) bool {
		l := strings.ToLower(n)
		return secretName(n) || (strings.Contains(l, "community") && !strings.Contains(l, "bgp"))
	}
	s = xmlElem.ReplaceAllStringFunc(s, func(m string) string {
		g := xmlElem.FindStringSubmatch(m)
		if g[1] != g[4] || !hideName(g[1]) || strings.TrimSpace(g[3]) == "" {
			return m
		}
		return "<" + g[1] + g[2] + ">(hidden)</" + g[4] + ">"
	})
	return xmlAttr.ReplaceAllStringFunc(s, func(m string) string {
		g := xmlAttr.FindStringSubmatch(m)
		if secretName(strings.TrimSuffix(strings.TrimSpace(g[1]), "=")) && g[2] != "" {
			return g[1] + `"(hidden)"`
		}
		return m
	})
}

var (
	cliHost = regexp.MustCompile(`(?i)^(\s*(?:no\s+)?snmp-server\s+host\s.*?(?:\bversion\s+(?:1|2c)\s+|\b(?:traps|informs)\s+(?:version\s+\S+\s+)?))(\S+)`)
	cliUser = regexp.MustCompile(`(?i)(\b(?:auth|priv)\s+(?:md5|sha[0-9]*|aes[0-9]*|des[0-9]*|3des)\s+)(\S+)`)
	cliSNMP = regexp.MustCompile(`(?i)^\s*config\s+.*snmp.*community\s*$`)
	cliName = regexp.MustCompile(`^(\s*set\s+(?:name|community-name)\s+).*$`)
)

// redactCLI hides what the word lists cannot see in the text of a CLI configuration: the community that follows "snmp-server
// host ... version 2c", the keys of "snmp-server user ... auth sha KEY priv aes KEY", and the names of the communities of a
// FortiOS "config system snmp community" block.
func redactCLI(s string) string {
	lines := strings.Split(s, "\n")
	blockIndent := -1
	for i, ln := range lines {
		ind := len(ln) - len(strings.TrimLeft(ln, " \t"))
		t := strings.TrimSpace(ln)
		switch {
		case blockIndent >= 0 && t == "end" && ind <= blockIndent:
			blockIndent = -1
		case blockIndent < 0 && cliSNMP.MatchString(ln):
			blockIndent = ind
		case blockIndent >= 0:
			ln = cliName.ReplaceAllString(ln, `${1}"(hidden)"`)
		}
		ln = cliHost.ReplaceAllString(ln, "${1}(hidden)")
		ln = cliUser.ReplaceAllString(ln, "${1}(hidden)")
		lines[i] = ln
	}
	return strings.Join(lines, "\n")
}

// RedactConfigValue is RedactConfig for a result of any type: a text is filtered as one, anything else as JSON.
func RedactConfigValue(v any) any {
	if Unfiltered() {
		return v
	}
	switch t := v.(type) {
	case string:
		return RedactConfig(t)
	case nil:
		return nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "(hidden: configuration could not be filtered)"
		}
		return RedactConfig(string(b))
	}
}
