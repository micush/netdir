package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"

	"netdir/internal/core"
)

// Read-only accounts.  A member of web.read_group who is in none of the web.group groups signs in and sees
// everything the GUI shows, but cannot change anything: the one gate every request passes (authedCT) refuses
// every method but GET and HEAD, and keeps three things back that a GET would hand over whole: the
// configuration versions (the whole file, keys and passwords included) and the keys and passwords inside the
// configuration the Configure pages read.  Logging out stays possible.

const ReadOnlyMsg = "This account is read-only: it can look at everything but cannot change anything."

// access says whether user may sign in and whether only to look: a member of a login group has full access,
// otherwise a member of a read-only group is let in read-only.  err is the lookup error of the login groups.
func (w *WebServer) access(user string, pol *core.WebConfig) (ok, readOnly bool, err error) {
	ok, err = w.Auth.InGroup(user, pol.Group)
	if ok {
		return true, false, nil
	}
	if pol.ReadGroup != "" {
		if ro, _ := w.Auth.InGroup(user, pol.ReadGroup); ro {
			return true, true, nil
		}
		err = nil // not in either: the plain "not a member" answer, whether or not the login groups exist here
	}
	return false, false, err
}

// ro reports whether s is a read-only account.
func (w *WebServer) ro(s *core.Session) bool {
	if s == nil {
		return false
	}
	w.Mu.Lock()
	defer w.Mu.Unlock()
	return s.ReadOnly
}

// readOnlyDenied is the rule: anything but a plain read is refused (logout excepted), and so are the pages
// that return a whole configuration file.
func readOnlyDenied(r *http.Request) bool {
	p := r.URL.Path
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return p != "/api/logout"
	}
	return p == "/api/versions/get" || p == "/api/versions/diff" || p == "/api/versions/download"
}

// readOnlyJob: the two POSTs that only start a look (ping/mtr, nmap) are let through for a request that came
// in-process (an MCP caller, or a node relaying one).  A read-only GUI user cannot reach this: the browser path
// (authed, second branch) still refuses every POST, and /api/proxy refuses non-GET for them.
func readOnlyJob(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	if p == "/api/proxy" { // the same job asked of another node: the path it carries is the one that counts
		p, _, _ = strings.Cut(r.URL.Query().Get("path"), "?")
	}
	if p == "/api/devices/mcp" { // device_mcp: a device's own tool list, or one of its tools that says it only reads
		return !deviceMCPWantsWrite(r)
	}
	return p == "/api/nettool" || p == "/api/scan"
}

// deviceMCPWantsWrite peeks at the body of a POST /api/devices/mcp (and puts it back) and says whether it asks
// for a write (device_mcp_write).  Anything it cannot read counts as a write.  Without write the handler runs only
// the tool list and the tools the device marks readOnlyHint (device.MCPCall), so a read-only caller can do no more.
func deviceMCPWantsWrite(r *http.Request) bool {
	if r.Body == nil {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil || len(b) > 1<<20 {
		return true
	}
	var a struct {
		Write json.RawMessage `json:"write"`
	}
	if json.Unmarshal(b, &a) != nil {
		return true
	}
	w := strings.TrimSpace(string(a.Write))
	return w != "" && w != "false" && w != "null"
}

// secretKeys are the configuration keys whose values a read-only account is not shown.
var SecretKeys = map[string]bool{"key": true, "password": true, "register_key": true, "secret": true, "sso_google_client_secret": true, "sso_entra_client_secret": true, "sso_oidc_client_secret": true, "ldap_bind_password": true,
	"token": true} // token: a device credential's API token (devices.go)

// redactSecrets returns v (a configuration) as generic JSON with the values of secretKeys replaced.
func redactSecrets(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return map[string]any{}
	}
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if s, ok := e.(string); ok && SecretKeys[strings.ToLower(k)] && s != "" {
					t[k] = "(hidden)"
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(out)
	return out
}

// ensureReadGroup makes the default read-only group (the one the installer creates) when it is in the setting and
// missing, so a daemon updated from the web page or by hand, which never ran install.sh, has it too and the Users
// page has a group to put people in.  Only the default name is ever created, and only by root; a directory group
// is never made here.
func EnsureReadGroup(cfg core.WebConfig) {
	def := core.DefaultWeb().ReadGroup
	if os.Geteuid() != 0 || def == "" {
		return
	}
	found := false
	for _, g := range SplitGroups(cfg.ReadGroup) {
		if g == def {
			found = true
		}
	}
	if !found {
		return
	}
	if _, err := user.LookupGroup(def); err == nil {
		return
	}
	if out, err := core.UsersRun("", "groupadd", "--system", def); err != nil {
		core.Warnf("web: could not create the read-only group %q: %s", def, core.FirstNonEmpty(out, err.Error()))
		return
	}
	core.Infof("web: created the read-only group %q (add people on the Users page)", def)
}
