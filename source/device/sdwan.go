package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Cisco Catalyst SD-WAN (Viptela), through the SD-WAN Manager (vManage) REST API below /dataservice.  The credential is a user
// name and a password.  The driver logs in once (POST /j_security_check with the form fields j_username and j_password, which
// sets the JSESSIONID cookie; the answer to a wrong login is the login page, with status 200), asks for the XSRF token
// (GET /dataservice/client/token, needed by Manager 19.2 and later for anything but a GET), logs in again when the session is
// refused or has expired, and logs out in Close.
//
//	show <resource>[/<sub resource>...] [key=value ...]    a GET below /dataservice: show device, show device/monitor, show alarms
//
// The device is the Manager: its facts name the Manager's version and count the devices it manages.  The devices it manages
// (edges, controllers) are read through show device and the paths below it.
//
// Not tried against a real Manager: the paths and the names of fields are from Cisco's API documentation.

func init() { Register("sdwan", newSDWAN) }

type sdwan struct {
	d    Device
	api  *apiClient
	user string
	pass string

	mu  sync.Mutex
	in  bool
	tok string
}

const sdBase = "/dataservice"

var sdSegRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// sdDeny are the parts of the API that hold accounts, certificates, settings with credentials, or the session itself.
var sdDeny = []string{"admin", "certificate", "settings", "token", "logout", "password", "credential", "keystore", "secret", "j_security_check", "disasterrecovery", "sso", "saml"}

func newSDWAN(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Catalyst SD-WAN Manager needs a user name and a password", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	return &sdwan{d: d, api: api, user: c.Username, pass: c.Password}, nil
}

func (s *sdwan) login(ctx context.Context, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.in && !force {
		return nil
	}
	form := url.Values{"j_username": {s.user}, "j_password": {s.pass}}.Encode()
	b, err := s.api.do(ctx, http.MethodPost, "/j_security_check", form, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"*/*"}})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if len(strings.TrimSpace(string(b))) > 0 { // the login page: the user name or the password is wrong
		return errors.New("login: the Manager refused the user name or the password")
	}
	s.in = true
	s.tok = ""
	if t, err := s.api.do(ctx, http.MethodGet, sdBase+"/client/token", nil, http.Header{"Accept": {"text/plain"}}); err == nil {
		s.tok = strings.TrimSpace(string(t))
		if strings.HasPrefix(s.tok, "<") || strings.HasPrefix(s.tok, "{") {
			s.tok = ""
		}
	}
	return nil
}

func (s *sdwan) auth() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := http.Header{}
	if s.tok != "" {
		h.Set("X-XSRF-TOKEN", s.tok)
	}
	return h
}

// get reads one path (it starts with "/dataservice") and decodes the JSON; an expired session is renewed once.
func (s *sdwan) get(ctx context.Context, p string) (any, error) {
	for renewed := false; ; renewed = true {
		if err := s.login(ctx, false); err != nil {
			return nil, err
		}
		b, err := s.api.do(ctx, http.MethodGet, p, nil, s.auth())
		var se *statusError
		expired := err != nil && errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(b)), "<") { // the login page instead of an answer
			expired = true
		}
		if expired && !renewed {
			if err := s.login(ctx, true); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil, nil
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON (the session may have been refused)", p)
		}
		return v, nil
	}
}

// data is the "data" of an answer ({"data": [...]}), or the answer.
func sdData(v any) any {
	if m, ok := v.(map[string]any); ok {
		if d, ok := m["data"]; ok {
			return d
		}
	}
	return v
}

func (s *sdwan) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Hostname: s.d.Name, Vendor: "Cisco", Model: "Catalyst SD-WAN Manager"}
	v, err := s.get(ctx, sdBase+"/client/server")
	if err != nil {
		return f, err
	}
	if m, ok := sdData(v).(map[string]any); ok {
		f.OSVersion = str(m["platformVersion"])
		if f.OSVersion == "" {
			f.OSVersion = str(m["version"])
		}
	}
	if dv, err := s.get(ctx, sdBase+"/device"); err == nil {
		kinds := map[string]int{}
		n := 0
		for _, r := range rows(sdData(dv)) {
			n++
			k := str(r["device-type"])
			if k == "" {
				k = "other"
			}
			kinds[k]++
		}
		parts := []string{}
		for _, k := range []string{"vmanage", "vsmart", "vbond", "vedge"} {
			if kinds[k] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", kinds[k], k))
			}
		}
		for k, c := range kinds {
			if k != "vmanage" && k != "vsmart" && k != "vbond" && k != "vedge" {
				parts = append(parts, fmt.Sprintf("%d %s", c, k))
			}
		}
		f.Model = fmt.Sprintf("Catalyst SD-WAN Manager, %d device(s)", n)
		if len(parts) > 0 {
			f.Model += ": " + strings.Join(parts, ", ")
		}
	}
	return f, nil
}

func (s *sdwan) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (s *sdwan) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (s *sdwan) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// sdRead checks a path for a read and gives it below /dataservice, with its query.
func sdRead(path string) (string, error) {
	p := path
	if !strings.HasPrefix(p, sdBase+"/") {
		p = sdBase + p
	}
	pp, q, _ := strings.Cut(p, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	segs := strings.Split(strings.Trim(strings.TrimPrefix(pp, sdBase), "/"), "/")
	if len(segs) < 1 || len(segs) > 8 {
		return "", errors.New("path: /dataservice/<resource>[/<sub resource>...] (see device_api_catalog)")
	}
	for _, g := range segs {
		if !sdSegRE.MatchString(g) {
			return "", fmt.Errorf("path: %q is not a resource name", g)
		}
		for _, d := range sdDeny {
			if strings.Contains(strings.ToLower(g), d) {
				return "", fmt.Errorf("path: %q holds accounts, certificates, settings or the session and is not read here", g)
			}
		}
	}
	return p, nil
}

func (s *sdwan) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show <resource>[/<sub resource>] [key=value ...]   for example: show device, show alarms, show device/monitor, show device/bfd/summary deviceId=1.1.1.1")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	q := url.Values{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !sdSegRE.MatchString(k) || v == "" || len(v) > 128 || strings.ContainsAny(v, "&#\"'`;<>") {
			return "", usage
		}
		q.Set(k, v)
	}
	p := "/" + strings.Trim(f[1], "/")
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	p, err := sdRead(p)
	if err != nil {
		return "", err
	}
	v, err := s.get(ctx, p)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(sdData(v)), "", "  ")
	return RedactText(string(b)), nil
}

func (s *sdwan) APIGet(ctx context.Context, path string) (any, bool, error) {
	p, err := sdRead(path)
	if err != nil {
		return nil, false, err
	}
	v, err := s.get(ctx, p)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (s *sdwan) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET paths of the Catalyst SD-WAN Manager API below /dataservice, with an optional ?key=value query. Only GET is sent. Accounts, certificates, settings and the session are not read. " +
			"The Manager's own API documentation is at https://<manager>/apidocs.",
		"examples": []string{"/dataservice/device", "/dataservice/device/monitor", "/dataservice/alarms", "/dataservice/device/counters",
			"/dataservice/device/interface?deviceId=<system-ip>", "/dataservice/device/bfd/summary?deviceId=<system-ip>", "/dataservice/template/device", "/dataservice/statistics/..."},
	}, nil
}

var sdRawDeny = []string{"admin", "certificate", "settings", "token", "logout", "password", "credential", "keystore", "secret", "disasterrecovery", "sso", "saml",
	"reboot", "reset", "upgrade", "install", "decommission", "tenantbackup", "backup", "restore"}

func sdRawGuard(_, p string) error {
	pp, q, _ := strings.Cut(p, "?")
	if q != "" {
		return errors.New("path: no query on a change")
	}
	if !strings.HasPrefix(pp, sdBase+"/") {
		return errors.New("path: the Catalyst SD-WAN Manager is changed below /dataservice/")
	}
	for _, g := range strings.Split(strings.Trim(strings.TrimPrefix(pp, sdBase), "/"), "/") {
		if !sdSegRE.MatchString(g) {
			return fmt.Errorf("path: %q is not a resource name", g)
		}
		for _, d := range sdRawDeny {
			if strings.Contains(strings.ToLower(g), d) {
				return fmt.Errorf("path: %q is not changed here (accounts, certificates, settings, backups, upgrades and restarts)", g)
			}
		}
	}
	return nil
}

func (s *sdwan) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	if len(r.Lines) > 0 {
		return RawResult{DryRun: dry}, errors.New("lines: the Catalyst SD-WAN Manager is changed with method, path and body")
	}
	if !strings.HasPrefix(r.Path, sdBase+"/") {
		r.Path = sdBase + "/" + strings.TrimPrefix(r.Path, "/")
	}
	if err := s.login(ctx, false); err != nil {
		return RawResult{DryRun: dry}, err
	}
	h := s.auth()
	auth := h.Clone()
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	return restRaw(ctx, restSpec{
		api: s.api, hdr: h, auth: auth, json: true,
		guard: sdRawGuard,
		alive: func(ctx context.Context) error { _, err := s.get(ctx, sdBase+"/client/server"); return err },
	}, r, dry)
}

func (s *sdwan) Close(ctx context.Context) {
	s.mu.Lock()
	in := s.in
	s.in = false
	s.mu.Unlock()
	if in {
		c, cancel := cleanupCtx()
		defer cancel()
		_, _ = s.api.do(c, http.MethodGet, "/logout?nocache=1", nil, http.Header{"Accept": {"*/*"}})
	}
	s.api.close()
}
