package device

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Juniper Junos through its REST API (https://www.juniper.net/documentation/us/en/software/junos/rest-api/): every Junos RPC is
// https://HOST:3443/rpc/<rpc-name>?<arguments> (GET), or POST /rpc with the RPC as XML.  On the device: "set system services rest
// https port 3443 server-certificate <name>" (and "set system services rest http" for plain HTTP, which this driver never uses),
// and a user whose class lets it run the operational commands (a login class with "view" permissions reads; "configure" and
// "all" write).  HTTP basic authentication; neither the user name nor the password is ever put in a URL.  Answers are asked in
// JSON (Accept: application/json); Junos wraps a value as [{"data": "x"}], which the driver unwraps.
//
//   - Facts: host name, model, release, chassis serial number, uptime.  Interfaces: the physical interfaces (admin and oper state,
//     speed, MAC, description) with the addresses of their units.  Neighbors: LLDP.  Config: the committed configuration, as text.
//   - Show: "show ..." commands (the CLI's own text, with | match, | except, | count, | display json, ...); the configuration,
//     keys and passwords are not shown.
//   - APIGet: /rpc/get-<name>?argument=value, any read RPC (get-route-information, get-bgp-neighbor-information, ...).
//   - RawChange (rw keys): Lines of configuration in set format ("set interfaces ge-0/0/1 description uplink", "delete ...",
//     "deactivate ...") are loaded into the candidate configuration, checked, committed with "commit confirmed 3" and confirmed
//     once the device still answers; if it does not, Junos rolls the change back by itself.  Or Method POST, Path /rpc and an XML
//     body with one RPC (clear-bgp-neighbor, request-reboot, ...).  A reboot is one line "request system reboot".
//
// Junos has no separate startup configuration: a committed configuration is the saved one, so Save changes nothing.

func init() { Register("junos", newJunos) }

type junos struct {
	d   Device
	api *apiClient
}

func newJunos(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Junos REST needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 3443)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	api.hdr.Set("Authorization", req.Header.Get("Authorization"))
	api.hdr.Set("User-Agent", "netdir")
	return &junos{d: d, api: api}, nil
}

func (j *junos) Close(context.Context) { j.api.close() }

// ---- reading the JSON of Junos ----

// jstr is the text of a Junos value: "x", {"data": "x"} or [{"data": "x"}].
func jstr(x any) string {
	switch t := x.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		if len(t) > 0 {
			return jstr(t[0])
		}
	case map[string]any:
		if d, ok := t["data"]; ok {
			return jstr(d)
		}
	}
	return strings.TrimSpace(str(x))
}

func jv(m map[string]any, key string) string { return jstr(m[key]) }

// jrows are the elements below a key, whether Junos wrote one object or a list.
func jrows(m map[string]any, key string) []map[string]any { return rows(m[key]) }

func jfirst(m map[string]any, key string) map[string]any {
	if r := jrows(m, key); len(r) > 0 {
		return r[0]
	}
	return map[string]any{}
}

// jattr is an attribute of an element: "up-time": [{"data": "...", "attributes": {"junos:seconds": "12"}}].
func jattr(m map[string]any, key, attr string) string {
	for _, e := range jrows(m, key) {
		if a, ok := e["attributes"].(map[string]any); ok {
			return jstr(a[attr])
		}
	}
	return ""
}

// junFlat writes a Junos answer without its {"data": ...} wrappers.
func junFlat(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if d, ok := t["data"]; ok && len(t) == 1 {
			return junFlat(d)
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = junFlat(x)
		}
		return out
	case []any:
		if len(t) == 1 {
			if m, ok := t[0].(map[string]any); ok && len(m) == 1 {
				if d, ok := m["data"]; ok {
					return junFlat(d)
				}
			}
		}
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = junFlat(x)
		}
		return out
	case string:
		return strings.TrimSpace(t)
	}
	return v
}

// jfind is the first text found under the key, anywhere in an answer.
func jfind(v any, keys ...string) string {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range keys {
			if x, ok := t[k]; ok {
				if s := jstr(x); s != "" {
					return s
				}
			}
		}
		names := make([]string, 0, len(t))
		for k := range t {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if s := jfind(t[k], keys...); s != "" {
				return s
			}
		}
	case []any:
		for _, x := range t {
			if s := jfind(x, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

// junErr is the message of the first rpc-error of severity "error" in an answer ("" when there is none).
func junErr(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"rpc-error", "xnm:error", "xnm:warning"} {
			for _, e := range rows(t[k]) {
				if k == "xnm:warning" || strings.EqualFold(jv(e, "error-severity"), "warning") {
					continue
				}
				msg := firstOf(jv(e, "error-message"), jv(e, "message"), "the device reported an error")
				if p := jv(e, "error-path"); p != "" {
					msg += " (at " + p + ")"
				}
				return msg
			}
		}
		for _, x := range t {
			if m := junErr(x); m != "" {
				return m
			}
		}
	case []any:
		for _, x := range t {
			if m := junErr(x); m != "" {
				return m
			}
		}
	}
	return ""
}

func junParse(b []byte) any {
	var v any
	if json.Unmarshal(b, &v) == nil {
		return v
	}
	return map[string]any{"output": strings.TrimSpace(string(b))} // text, or XML: not JSON
}

var junJSON = http.Header{"Accept": {"application/json"}}
var junXML = http.Header{"Accept": {"application/json"}, "Content-Type": {"application/xml"}}

// get reads one RPC (GET /rpc/<name>?args).
func (j *junos) get(ctx context.Context, rpc string, q url.Values) (any, error) {
	p := "/rpc/" + rpc
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	b, err := j.api.do(ctx, http.MethodGet, p, nil, junJSON)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", p, err)
	}
	v := junParse(b)
	if msg := junErr(v); msg != "" {
		return nil, fmt.Errorf("GET %s: %s", p, msg)
	}
	return v, nil
}

// post sends one RPC as XML (POST /rpc).
func (j *junos) post(ctx context.Context, body string) (any, error) {
	b, err := j.api.do(ctx, http.MethodPost, "/rpc", body, junXML)
	if err != nil {
		return nil, err
	}
	v := junParse(b)
	if msg := junErr(v); msg != "" {
		return v, errors.New(msg)
	}
	return v, nil
}

func xmlEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func jtop(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// ---- the named reads ----

func (j *junos) Facts(ctx context.Context) (Facts, error) {
	v, err := j.get(ctx, "get-software-information", nil)
	if err != nil {
		return Facts{}, err
	}
	sw := jfirst(jtop(v), "software-information")
	f := Facts{Hostname: firstOf(jv(sw, "host-name"), j.d.Address), Vendor: "Juniper", Model: jv(sw, "product-model"), OSVersion: jv(sw, "junos-version")}
	if f.OSVersion == "" {
		for _, p := range jrows(sw, "package-information") {
			if jv(p, "name") == "junos" || jv(p, "name") == "os-kernel" {
				f.OSVersion = jv(p, "comment")
			}
		}
	}
	if inv, err := j.get(ctx, "get-chassis-inventory", nil); err == nil {
		f.Serial = jv(jfirst(jfirst(jtop(inv), "chassis-inventory"), "chassis"), "serial-number")
	}
	if up, err := j.get(ctx, "get-system-uptime-information", nil); err == nil {
		ui := jfirst(jfirst(jtop(up), "system-uptime-information"), "uptime-information")
		if n, err := strconv.ParseInt(jattr(ui, "up-time", "junos:seconds"), 10, 64); err == nil {
			f.UptimeS = n
		}
	}
	return f, nil
}

var junSpeedRE = regexp.MustCompile(`(?i)^([0-9]+)\s*([gmk]?)(bps)?$`)

func junSpeed(s string) int64 {
	m := junSpeedRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	switch strings.ToLower(m[2]) {
	case "g":
		return n * 1000
	case "k":
		return n / 1000
	}
	return n
}

func (j *junos) Interfaces(ctx context.Context) ([]Interface, error) {
	v, err := j.get(ctx, "get-interface-information", nil)
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, p := range jrows(jfirst(jtop(v), "interface-information"), "physical-interface") {
		i := Interface{Name: jv(p, "name"), Description: jv(p, "description"), SpeedMbps: junSpeed(jv(p, "speed")), MAC: jv(p, "current-physical-address")}
		if i.Name == "" {
			continue
		}
		if a := jv(p, "admin-status"); a != "" {
			i.AdminUp = boolp(strings.EqualFold(a, "up"))
		}
		if o := jv(p, "oper-status"); o != "" {
			i.OperUp = boolp(strings.EqualFold(o, "up"))
		}
		for _, l := range jrows(p, "logical-interface") {
			for _, fam := range jrows(l, "address-family") {
				for _, a := range jrows(fam, "interface-address") {
					if ip := jv(a, "ifa-local"); ip != "" {
						i.Addresses = append(i.Addresses, ip)
					}
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}

func (j *junos) Neighbors(ctx context.Context) ([]Neighbor, error) {
	v, err := j.get(ctx, "get-lldp-neighbors-information", nil)
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	for _, n := range jrows(jfirst(jtop(v), "lldp-neighbors-information"), "lldp-neighbor-information") {
		out = append(out, Neighbor{LocalPort: firstOf(jv(n, "lldp-local-port-id"), jv(n, "lldp-local-interface")), RemoteName: jv(n, "lldp-remote-system-name"),
			RemotePort: firstOf(jv(n, "lldp-remote-port-id"), jv(n, "lldp-remote-port-description")), RemoteDesc: jv(n, "lldp-remote-port-description"), Protocol: "lldp"})
	}
	return out, nil
}

func (j *junos) Config(ctx context.Context) (string, error) {
	v, err := j.post(ctx, `<get-configuration database="committed" format="text"/>`)
	if err != nil {
		return "", err
	}
	if s := jfind(v, "configuration-text", "configuration-output", "output"); s != "" {
		return s, nil
	}
	return "", errors.New("the device sent no configuration text")
}

// ---- show ----

// junShowDenied: the commands of the CLI that print the configuration or secrets.  The CLI takes any unique prefix of a word, so
// "conf" and "config" are "configuration".
var junShowWords = []string{"secret", "password", "pre-shared", "private-key", "authentication-key", "encrypted", "tacplus", "radius-server"}

func junShowDenied(cmd string) error {
	c, _, _ := strings.Cut(strings.ToLower(cmd), "|")
	for _, w := range strings.Fields(c) {
		if len(w) >= 4 && strings.HasPrefix("configuration", w) {
			return errors.New("show configuration holds the device's secrets and is not available here; ask for a part (the device_* tools or a show of one feature)")
		}
		for _, d := range junShowWords {
			if strings.Contains(w, d) {
				return fmt.Errorf("%q: commands about secrets are not shown here", w)
			}
		}
	}
	return nil
}

func (j *junos) Show(ctx context.Context, cmd string) (string, error) {
	cmd, err := CheckShow(cmd)
	if err != nil {
		return "", err
	}
	if err := junShowDenied(cmd); err != nil {
		return "", err
	}
	v, err := j.post(ctx, `<command format="text">`+xmlEsc(cmd)+`</command>`)
	if err != nil {
		return "", err
	}
	if s, ok := jtop(v)["output"].(string); ok {
		return s, nil
	}
	if s := jfind(v, "output"); s != "" {
		return s, nil
	}
	b, _ := json.MarshalIndent(obsScrub(Redact(junFlat(v))), "", "  ")
	return string(b), nil
}

// ---- reading through the API ----

var (
	junReadRE = regexp.MustCompile(`^/rpc/get-[a-z0-9-]{1,100}$`)
	junKeyRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,60}$`)
)

// junRPCDenied are the words of a read RPC's name that read the configuration or secrets.
func junRPCDenied(name string) error {
	if strings.Contains(name, "config") {
		return errors.New("path: the configuration holds the device's secrets and is not read through the API (the device_* tools read the parts)")
	}
	for _, w := range []string{"secret", "password", "key", "license", "authentication", "tacplus", "radius", "ldap", "certificate", "pki", "user", "login"} {
		if strings.Contains(name, w) {
			return fmt.Errorf("path: %q is about secrets, keys or users and is not read here", name)
		}
	}
	return nil
}

func (j *junos) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = strings.TrimSuffix(pp, "/")
	if !junReadRE.MatchString(pp) {
		return nil, false, errors.New("path: /rpc/get-<name>?argument=value, such as /rpc/get-route-information?destination=10.0.0.0/8 (see device_api_catalog)")
	}
	if err := junRPCDenied(strings.TrimPrefix(pp, "/rpc/")); err != nil {
		return nil, false, err
	}
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return nil, false, errors.New("path: the query is not valid")
	}
	for k, vs := range vals {
		if !junKeyRE.MatchString(k) {
			return nil, false, fmt.Errorf("path: %q is not an argument name", k)
		}
		for _, v := range vs {
			if len(v) > 512 || junCtlRE.MatchString(v) {
				return nil, false, fmt.Errorf("path: the value of %q is too long, or holds a control character", k)
			}
		}
	}
	v, err := j.get(ctx, strings.TrimPrefix(pp, "/rpc/"), vals)
	if err != nil {
		return nil, false, err
	}
	return obsScrub(Redact(junFlat(v))), false, nil
}

func (j *junos) APICatalog(context.Context) (any, error) {
	ex := []string{"/rpc/get-software-information", "/rpc/get-system-information", "/rpc/get-chassis-inventory", "/rpc/get-system-uptime-information", "/rpc/get-interface-information",
		"/rpc/get-interface-information?terse=", "/rpc/get-interface-information?interface-name=ge-0/0/0&extensive=", "/rpc/get-route-information",
		"/rpc/get-route-information?destination=10.0.0.0/8", "/rpc/get-bgp-neighbor-information", "/rpc/get-ospf-neighbor-information", "/rpc/get-isis-adjacency-information",
		"/rpc/get-lldp-neighbors-information", "/rpc/get-arp-table-information", "/rpc/get-ethernet-switching-table-information", "/rpc/get-environment-information",
		"/rpc/get-alarm-information", "/rpc/get-system-storage", "/rpc/get-firewall-policies", "/rpc/get-security-zones-information"}
	return map[string]any{
		"how": "Every Junos RPC that reads is /rpc/get-<name>; arguments are query parameters (a flag has an empty value: ?terse=). The name of an RPC is shown by " +
			"\"show <command> | display xml rpc\" (device_show). The configuration, keys, passwords and users are not read. Changes are device_change_raw.",
		"examples": ex,
		"tip":      "device_show takes any show command: show route, show bgp summary, show chassis alarms, show system uptime | display json.",
	}, nil
}

// ---- changes ----

var junCtlRE = regexp.MustCompile(`[\x00-\x1f\x7f]`)

const junConfirmMinutes = 3

var (
	junLineFirst = map[string]bool{"set": true, "delete": true, "deactivate": true, "activate": true, "insert": true, "annotate": true}
	// what a change does not touch: who may sign in, and the ways in (REST, NETCONF, SSH, the management interfaces and the routing
	// engines' own groups)
	junLineDeny = regexp.MustCompile(`^(system\s+(login|root-authentication|radius-server|tacplus-server|authentication-order|services\s+(rest|netconf|ssh|web-management|xnm-clear-text|xnm-ssl|outbound-ssh))\b|` +
		`interfaces\s+(fxp0|em0|em1|me0|vme|re0|re1)\b|groups\s+(re0|re1|node0|node1)\b|apply-groups\b)`)
	// RPCs that are not sent as they are: the commit and the lock are the driver's; zeroize and power off cannot be undone
	junRPCDeny = regexp.MustCompile(`^(load-configuration|commit-configuration|commit-check|lock-configuration|unlock-configuration|open-configuration|close-configuration|` +
		`discard-changes|kill-session|close-session|request-system-zeroize|request-power-off|request-halt|request-system-halt|request-system-power-off|request-system-snapshot|` +
		`request-package-.*|request-system-software-.*|request-vmhost-.*|get-configuration|edit-config|copy-config|file-.*|save-.*|rollback.*)$`)
	junRPCRootRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,100}$`)
	junRebootRE  = regexp.MustCompile(`^request\s+system\s+reboot(\s+now)?$`)
)

func junLines(r Raw) ([]string, error) {
	if r.Method != "" || r.Path != "" || r.Body != "" {
		return nil, errors.New("method, path and body: lines of configuration are sent alone (to send an RPC use method POST, path /rpc and the XML in the body)")
	}
	var out []string
	for _, l := range r.Lines {
		if junCtlRE.MatchString(strings.TrimSpace(l)) {
			return nil, fmt.Errorf("line %q: has control characters (one statement a line)", l)
		}
		l = strings.Join(strings.Fields(l), " ")
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "/*") {
			continue
		}
		if len(l) > 512 {
			return nil, fmt.Errorf("line %q: longer than 512 characters or has control characters", l)
		}
		w := strings.Fields(strings.ToLower(l))
		if !junLineFirst[w[0]] {
			return nil, fmt.Errorf("line %q: a line is set, delete, deactivate, activate, insert or annotate (set format)", l)
		}
		if len(w) < 2 || (w[0] == "delete" && len(w) < 3) {
			return nil, fmt.Errorf("line %q: too little: a delete names a statement below a top level (\"delete interfaces ge-0/0/1\"), never a whole hierarchy", l)
		}
		if junLineDeny.MatchString(strings.Join(w[1:], " ")) {
			return nil, fmt.Errorf("line %q: not sent (users and login, the REST, NETCONF and SSH services, and the management interfaces are not changed here)", l)
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, errors.New("lines: there is nothing to send")
	}
	if len(out) > rawMaxLines {
		return nil, fmt.Errorf("lines: more than %d", rawMaxLines)
	}
	return out, nil
}

// junRoot is the name of the one element a body holds ("" when it is not exactly one well-formed element).
func junRoot(body string) (string, error) {
	d := xml.NewDecoder(strings.NewReader(body))
	root, depth := "", 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("body: not well-formed XML: %v", err)
		}
		switch x := t.(type) {
		case xml.StartElement:
			if depth == 0 {
				if root != "" {
					return "", errors.New("body: one RPC, one element")
				}
				root = x.Name.Local
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.ProcInst, xml.Directive:
			return "", errors.New("body: no processing instruction or DTD")
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(x)) != "" {
				return "", errors.New("body: text outside the RPC")
			}
		}
	}
	if root == "" {
		return "", errors.New("body: an RPC such as <clear-bgp-neighbor><neighbor>10.0.0.1</neighbor></clear-bgp-neighbor>")
	}
	return root, nil
}

func (j *junos) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if len(r.Lines) == 1 && r.Method == "" && r.Path == "" && r.Body == "" && junRebootRE.MatchString(strings.ToLower(strings.Join(strings.Fields(r.Lines[0]), " "))) {
		return j.sendRPC(ctx, "request-reboot", `<request-reboot/>`, dry)
	}
	if len(r.Lines) == 0 {
		return j.rawRPC(ctx, r, dry)
	}
	lines, err := junLines(r)
	if err != nil {
		return res, err
	}
	// the candidate configuration is shared: changes somebody else has made and not committed are not committed with these
	diff, err := j.diff(ctx)
	if err != nil {
		return res, fmt.Errorf("the candidate configuration could not be compared (nothing was changed): %w", err)
	}
	if strings.TrimSpace(diff) != "" {
		return res, fmt.Errorf("the candidate configuration already holds uncommitted changes (nothing was changed); commit or roll them back on the device first:\n%s", rawTrunc([]byte(diff)))
	}
	load := `<load-configuration action="set" format="text"><configuration-set>` + xmlEsc(strings.Join(lines, "\n")) + `</configuration-set></load-configuration>`
	if _, err := j.post(ctx, load); err != nil {
		j.rollback0(ctx)
		return res, fmt.Errorf("the device refused the lines (nothing was committed): %w", err)
	}
	diff, err = j.diff(ctx)
	if err != nil {
		j.rollback0(ctx)
		return res, fmt.Errorf("the change could not be compared (nothing was committed): %w", err)
	}
	res.Before = rawTrunc([]byte(diff))
	if _, err := j.post(ctx, `<commit-configuration><check/></commit-configuration>`); err != nil {
		j.rollback0(ctx)
		return res, fmt.Errorf("the device's commit check refused the change (nothing was committed): %w", err)
	}
	if strings.TrimSpace(diff) == "" {
		j.rollback0(ctx)
		res.Note = "the lines change nothing: the configuration already is so"
		return res, nil
	}
	if dry {
		j.rollback0(ctx)
		res.Note = "Before is the device's own diff of the change and it passed the commit check; nothing was committed"
		return res, nil
	}
	if _, err := j.post(ctx, fmt.Sprintf(`<commit-configuration><confirmed/><confirm-timeout>%d</confirm-timeout><log>netdir</log></commit-configuration>`, junConfirmMinutes)); err != nil {
		j.rollback0(ctx)
		return res, fmt.Errorf("the commit failed (nothing was committed): %w", err)
	}
	res.Applied = true
	// the change is live for three minutes; Junos undoes it by itself unless it is confirmed
	if _, err := j.get(ctx, "get-software-information", nil); err != nil {
		res.Note = fmt.Sprintf("the change was committed with a %d minute timer, but the device did not answer afterwards: it undoes the change by itself when the timer runs out", junConfirmMinutes)
		return res, fmt.Errorf("the device did not answer after the change: %w", err)
	}
	if _, err := j.post(ctx, `<commit-configuration><log>netdir</log></commit-configuration>`); err != nil {
		res.Note = "the device answered, but confirming the commit failed: the change is undone when the timer runs out"
		return res, fmt.Errorf("confirming the commit: %w", err)
	}
	res.Saved = true
	res.Note = "Junos keeps no separate startup configuration: the committed configuration is the saved one"
	return res, nil
}

func (j *junos) diff(ctx context.Context) (string, error) {
	v, err := j.post(ctx, `<get-configuration compare="rollback" rollback="0" format="text"/>`)
	if err != nil {
		return "", err
	}
	return jfind(v, "configuration-output", "output"), nil
}

// rollback0 puts the candidate configuration back to the committed one.
func (j *junos) rollback0(ctx context.Context) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	_, _ = j.post(rctx, `<load-configuration rollback="0"/>`)
}

// rawRPC: Method POST, Path /rpc, Body the RPC as XML.
func (j *junos) rawRPC(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if m := strings.ToUpper(strings.TrimSpace(r.Method)); m != http.MethodPost {
		return res, fmt.Errorf("method %q: use POST with path /rpc and the RPC as XML in the body, or lines of configuration (set format)", r.Method)
	}
	if p := strings.TrimSuffix(strings.TrimSpace(r.Path), "/"); p != "/rpc" {
		return res, fmt.Errorf("path %q: use /rpc", r.Path)
	}
	if len(r.Body) > rawMaxBody || strings.ContainsRune(r.Body, 0) {
		return res, errors.New("body: larger than 256 KB, or not text")
	}
	root, err := junRoot(strings.TrimSpace(r.Body))
	if err != nil {
		return res, err
	}
	if !junRPCRootRE.MatchString(root) || junRPCDeny.MatchString(root) {
		return res, fmt.Errorf("body: the RPC %q is not sent here (configuration changes are lines of configuration; locks, commits, zeroize, power off, software and file operations are not sent)", root)
	}
	if strings.Contains(root, "password") || strings.Contains(root, "secret") || strings.Contains(root, "login") {
		return res, fmt.Errorf("body: the RPC %q is about secrets or login and is not sent here", root)
	}
	if strings.HasPrefix(root, "get-") && !strings.Contains(root, "config") {
		return res, errors.New("body: that RPC only reads: use device_api_get (/rpc/" + root + ") or device_show")
	}
	return j.sendRPC(ctx, root, strings.TrimSpace(r.Body), dry)
}

func (j *junos) sendRPC(ctx context.Context, root, body string, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	reboot := root == "request-reboot"
	if dry {
		res.Note = "would send the RPC " + root + "; nothing was changed"
		return res, nil
	}
	v, err := j.post(ctx, body)
	if reboot && connEnded(err) {
		res.Applied, res.Note = true, rebootNote
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("the device refused %s: %w", root, err)
	}
	res.Applied = true
	b, _ := json.Marshal(obsScrub(Redact(junFlat(v))))
	res.Answer = rawTrunc(b)
	if reboot {
		res.Note = rebootNote
	} else {
		res.Note = "an RPC is not put back by this program"
	}
	return res, nil
}
