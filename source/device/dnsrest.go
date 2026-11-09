package device

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// What the two hosted-DNS drivers (NS1 and RcodeZero) share: the shape of a path, a zone name and a record name, and the read of a
// path whose answer may be JSON or, for a zone file, text.

var (
	dnsPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~*%-]+(/[A-Za-z0-9._~*%-]+)*$`)
	dnsZoneRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$`)
	dnsNameRE = regexp.MustCompile(`^[A-Za-z0-9_*@][A-Za-z0-9_.*@-]{0,252}$`)
	dnsTypeRE = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)
	dnsKindRE = regexp.MustCompile(`^[a-z][a-z_]{1,24}$`)
)

// dnsPrefix reads the option "prefix" (the path the API is served below): def when it is empty, "" for none.
func dnsPrefix(d Device, def string) (string, error) {
	p := strings.TrimRight(strings.TrimSpace(d.Options["prefix"]), "/")
	switch {
	case p == "" && strings.TrimSpace(d.Options["prefix"]) == "":
		return def, nil
	case p == "" || strings.EqualFold(p, "none"):
		return "", nil
	case !centPrefixRE.MatchString(p) || strings.Contains(p, ".."):
		return "", errors.New("option prefix is the path the API is served below, such as " + def + ", or none")
	}
	return p, nil
}

// dnsRel takes the prefix off a path that was given with it.
func dnsRel(prefix, p string) string {
	if prefix != "" && (p == prefix || strings.HasPrefix(p, prefix+"/")) {
		return p[len(prefix):]
	}
	return p
}

// dnsRead is one GET: the answer as JSON when it is, else as text.
func dnsRead(ctx context.Context, c *apiClient, path string) (any, bool, error) {
	b, err := c.do(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, false, nil
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		return v, false, nil
	}
	return RedactText(string(b)), true, nil
}

// dnsSegs are the segments of a path without the query.
func dnsSegs(p string) []string {
	p, _, _ = strings.Cut(p, "?")
	return strings.Split(strings.Trim(p, "/"), "/")
}

// dnsRecordRow keeps the fields of a record or an rrset that tell what it is.
func dnsRecordRow(m map[string]any) map[string]any {
	return centPick(m, "id", "domain", "name", "type", "ttl", "tier", "link", "short_answers", "answers", "records", "filters", "disabled", "comments", "changetype")
}

// dnsSecretKey names a field of an answer that holds a credential: a monitor's authorization header, a data source's key.
var dnsSecretKey = regexp.MustCompile(`(?i)auth|credential|header|api_?key|secret|token|pass|tsig|private`)

// dnsHide hides the value of every field named like a credential, whatever it holds (a list or an object too), and then the usual
// hiding by name and by text is done by Redact and obsScrub.
func dnsHide(v any) any {
	if Unfiltered() {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if dnsSecretKey.MatchString(k) && x != nil {
				t[k] = "(hidden)"
				continue
			}
			t[k] = dnsHide(x)
		}
	case []any:
		for i, x := range t {
			t[i] = dnsHide(x)
		}
	case []map[string]any:
		for _, x := range t {
			dnsHide(x)
		}
	}
	return v
}

// dnsText is an answer as indented JSON with the credentials in it hidden.
func dnsText(v any) string { return obsText(dnsHide(v)) }
