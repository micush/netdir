package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Arbitrary configuration changes (RawChanger), for every platform that has a way to be written.  Where the typed changes of
// change.go are a fixed set of safe verbs, a Raw is the platform's own write: a REST request (iosxe, aoscx, fortios, nios,
// bigip, technitium), a PAN-OS XML API action, or lines of CLI configuration (eos, nxos).  What the daemon adds around it:
//
//   - the call is refused for anyone who is not read-write (checked by the caller, as for typed changes);
//   - the request is checked before it leaves: the method, a path inside the platform's configuration tree, no way to reach
//     login, users, key files, reload or file operations (each platform's guard says what);
//   - a dry run sends nothing that changes the device: it returns the "before" copy of what the path holds (REST), or the
//     device's own diff (EOS);
//   - the "before" copy is kept and put back (PUT) when the request fails in a way that may have changed something (a 5xx, a
//     lost connection) or when the device no longer answers after it; EOS applies with a commit timer and confirms it only after
//     the switch answered again; NX-OS takes a checkpoint and rolls back to it;
//   - the answer and the "before" copy have secrets hidden (RedactText).
//
// What it cannot do: tell that the change is what the caller meant, read the result back for equality (devices normalise what
// they store), or undo a POST (create) or a DELETE over REST.  The result says what was and was not done.

// Raw is one change in the platform's own terms.  REST platforms: Method (POST, PUT, PATCH, DELETE) and Path (below the
// platform's root), Body as text.  PAN-OS: Method is the action (set, edit, delete, rename, move), Path the XPath, Body the
// element.  EOS and NX-OS: Lines.  Save makes the change survive a reboot (save config, write memory, commit).
type Raw struct {
	Method string   `json:"method,omitempty"`
	Path   string   `json:"path,omitempty"`
	Body   string   `json:"body,omitempty"`
	Lines  []string `json:"lines,omitempty"`
	Save   bool     `json:"save,omitempty"`
}

// RawResult says what happened.
type RawResult struct {
	DryRun     bool   `json:"dry_run"`
	Applied    bool   `json:"applied"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Saved      bool   `json:"saved,omitempty"`
	Before     string `json:"before,omitempty"`
	Answer     string `json:"answer,omitempty"`
	Note       string `json:"note,omitempty"`
}

// RawChanger is implemented by a driver that can be written.
type RawChanger interface {
	RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error)
}

const (
	rawMaxBody  = 256 << 10
	rawMaxLines = 500
	rawMaxOut   = 8 << 10
)

var ctlRE = regexp.MustCompile(`[\x00-\x1f\x7f ]`)

func rawTrunc(b []byte) string {
	s := RedactText(strings.TrimSpace(string(b)))
	if len(s) > rawMaxOut {
		s = s[:rawMaxOut] + "…"
	}
	return s
}

// checkREST checks what every REST platform checks, and returns the request with its method in capitals.
func (r Raw) checkREST(methods ...string) (Raw, error) {
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	ok := false
	for _, m := range methods {
		ok = ok || m == r.Method
	}
	if !ok {
		return r, fmt.Errorf("method %q: use one of %s", r.Method, strings.Join(methods, ", "))
	}
	if len(r.Lines) > 0 {
		return r, errors.New("lines: this platform is changed with a method, a path and a body, not lines of configuration")
	}
	if !strings.HasPrefix(r.Path, "/") || len(r.Path) > 2000 || ctlRE.MatchString(r.Path) || strings.Contains(r.Path, "..") ||
		strings.Contains(r.Path, "#") || strings.Contains(r.Path, "//") {
		return r, fmt.Errorf("path %q: a path that starts with / and has no spaces, .. or #", r.Path)
	}
	if len(r.Body) > rawMaxBody || strings.ContainsRune(r.Body, 0) {
		return r, errors.New("body: larger than 256 KB, or not text")
	}
	return r, nil
}

// restSpec is what a platform gives restRaw.
type restSpec struct {
	api     *apiClient
	hdr     http.Header                       // Content-Type and Accept of a write
	auth    http.Header                       // headers every request needs, also one without a body (Proxmox: its token or ticket)
	json    bool                              // the body must be JSON
	guard   func(method, path string) error   // what this platform refuses
	prep    func(ctx context.Context) error   // a login
	wire    func(path string) string          // the path as sent (FortiOS adds its vdom)
	restore func(snapshot []byte) (any, bool) // what to PUT to put the old state back
	alive   func(ctx context.Context) error   // a read that must still work after the change
	save    func(ctx context.Context) error
	reboot  func(Raw) bool // says that the request is a restart (rawreboot.go): no guard, no read before or after, no put-back
}

func restRaw(ctx context.Context, s restSpec, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	r, err := r.checkREST(http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete)
	if err != nil {
		return res, err
	}
	if s.json && strings.TrimSpace(r.Body) != "" && !json.Valid([]byte(r.Body)) {
		return res, errors.New("body: not valid JSON")
	}
	if r.Method != http.MethodDelete && strings.TrimSpace(r.Body) == "" && r.Method != http.MethodPost {
		return res, fmt.Errorf("body: %s needs one", r.Method)
	}
	rb := s.reboot != nil && s.reboot(r)
	if !rb {
		if err := s.guard(r.Method, r.Path); err != nil {
			return res, err
		}
	}
	if s.prep != nil {
		if err := s.prep(ctx); err != nil {
			return res, err
		}
	}
	wire := func(p string) string {
		if s.wire != nil {
			return s.wire(p)
		}
		return p
	}
	var snap []byte
	if r.Method != http.MethodPost && !rb {
		b, err := s.api.do(ctx, http.MethodGet, wire(r.Path), nil, s.hdr)
		var se *statusError
		switch {
		case errors.As(err, &se) && se.Code == http.StatusNotFound:
			res.Note = "the path holds nothing now, so there is nothing to put back"
		case err != nil:
			return res, fmt.Errorf("the copy of what is there now could not be read (nothing was changed): %w", err)
		default:
			snap = b
			res.Before = rawTrunc(b)
		}
	}
	if dry {
		res.Note = strings.TrimSpace(fmt.Sprintf("would send %s %s; nothing was changed. %s", r.Method, r.Path, res.Note))
		return res, nil
	}
	hdr := s.auth
	if r.Body != "" {
		hdr = s.hdr
	}
	if rb && r.Save && s.save != nil {
		if err := s.save(ctx); err != nil {
			return res, fmt.Errorf("saving the configuration before the restart failed (nothing was restarted): %w", err)
		}
		res.Saved = true
	}
	ans, err := s.api.do(ctx, r.Method, wire(r.Path), r.Body, hdr)
	if rb && connEnded(err) {
		res.Applied, res.Note = true, rebootNote
		return res, nil
	}
	if err != nil {
		var se *statusError
		// a refused request (4xx) changed nothing; any other failure may have
		if !(errors.As(err, &se) && se.Code < 500) {
			s.putBack(ctx, r, snap, wire, &res)
		}
		return res, fmt.Errorf("%s %s: %w", r.Method, r.Path, err)
	}
	res.Applied = true
	res.Answer = rawTrunc(ans)
	if rb {
		res.Note = rebootNote
		return res, nil
	}
	if s.alive != nil {
		if aerr := s.alive(ctx); aerr != nil {
			s.putBack(ctx, r, snap, wire, &res)
			return res, fmt.Errorf("the device did not answer a read after the change: %w", aerr)
		}
	}
	if r.Save && s.save != nil {
		if err := s.save(ctx); err != nil {
			return res, fmt.Errorf("the change is applied but saving it failed: %w", err)
		}
		res.Saved = true
	}
	return res, nil
}

// putBack restores the copy taken before a PUT or PATCH; a POST or a DELETE cannot be put back this way, and the result says so.
func (s restSpec) putBack(ctx context.Context, r Raw, snap []byte, wire func(string) string, res *RawResult) {
	if snap == nil || s.restore == nil || (r.Method != http.MethodPut && r.Method != http.MethodPatch) {
		res.Note = strings.TrimSpace(res.Note + " The change could not be put back automatically: the copy in 'before' shows what was there.")
		return
	}
	body, ok := s.restore(snap)
	if !ok {
		res.Note = strings.TrimSpace(res.Note + " The old state could not be put back automatically: the copy in 'before' shows what was there.")
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if _, err := s.api.do(rctx, http.MethodPut, wire(r.Path), body, s.hdr); err != nil {
		res.Note = strings.TrimSpace(res.Note + " Putting the old state back failed: " + err.Error())
		return
	}
	res.RolledBack = true
}

func hasSeg(path string, segs ...string) bool {
	p := strings.SplitN(path, "?", 2)[0]
	for _, part := range strings.Split(p, "/") {
		for _, s := range segs {
			if strings.EqualFold(part, s) {
				return true
			}
		}
	}
	return false
}

// checkLines checks CLI configuration lines: no control characters, no comments, a bounded number, and none the platform's
// deny expression (compared in lower case) matches.
func checkLines(r Raw, deny *regexp.Regexp) ([]string, error) {
	if r.Method != "" || r.Path != "" || r.Body != "" {
		return nil, errors.New("method, path and body: this platform is changed with lines of configuration")
	}
	var out []string
	for _, l := range r.Lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "#") {
			continue
		}
		if len(l) > 512 || regexp.MustCompile(`[\x00-\x1f\x7f]`).MatchString(l) {
			return nil, fmt.Errorf("line %q: longer than 512 characters or has control characters", l)
		}
		if deny.MatchString(strings.ToLower(l)) {
			return nil, fmt.Errorf("line %q: not sent (it ends the session, reloads, erases, copies files, runs a shell, or cuts the management access)", l)
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
