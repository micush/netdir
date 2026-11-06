package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The REST platforms' RawChange.  Each gives restRaw its guard (what stays out of reach), the login it needs, the read that
// proves the device still answers, and the way to put an old state back.

func jsonHdr() http.Header {
	return http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}}
}

// ---- Cisco IOS-XE: RESTCONF ----

func (x *iosxe) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	h := http.Header{"Content-Type": {yangJSON}, "Accept": {yangJSON}}
	return restRaw(ctx, restSpec{
		api: x.api, hdr: h, json: true,
		guard: func(_, p string) error {
			if !strings.HasPrefix(p, "/restconf/data/") {
				return errors.New("path: IOS-XE is changed below /restconf/data/ (operations such as reload are not sent)")
			}
			return nil
		},
		restore: func(b []byte) (any, bool) { return b, len(b) > 0 },
		alive: func(ctx context.Context) error {
			_, err := x.get(ctx, "Cisco-IOS-XE-native:native/hostname")
			return err
		},
		save: func(ctx context.Context) error {
			_, err := x.api.do(ctx, http.MethodPost, "/restconf/operations/cisco-ia:save-config", nil, h)
			return err
		},
	}, r, dry)
}

// ---- Aruba AOS-CX: REST ----

func (a *aoscx) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	root := a.path("/")
	return restRaw(ctx, restSpec{
		api: a.api, hdr: jsonHdr(), json: true,
		guard: func(_, p string) error {
			if !strings.HasPrefix(p, root) {
				return fmt.Errorf("path: AOS-CX is changed below %s", root)
			}
			if hasSeg(p, "login", "logout", "users", "fullconfigs") {
				return errors.New("path: login, logout, users and whole configurations are not changed here")
			}
			return nil
		},
		prep:    a.login,
		restore: func(b []byte) (any, bool) { return b, len(b) > 0 },
		alive:   func(ctx context.Context) error { _, err := a.get(ctx, "/system?attributes=hostname"); return err },
	}, r, dry)
}

// ---- Fortinet FortiOS: REST cmdb ----

func (f *fortios) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	return restRaw(ctx, restSpec{
		api: f.api, hdr: jsonHdr(), json: true, wire: f.path,
		guard: func(_, p string) error {
			if !strings.HasPrefix(p, "/api/v2/cmdb/") {
				return errors.New("path: FortiOS is changed below /api/v2/cmdb/")
			}
			if strings.HasPrefix(p, "/api/v2/cmdb/system/admin") || strings.HasPrefix(p, "/api/v2/cmdb/system/api-user") ||
				strings.HasPrefix(p, "/api/v2/cmdb/system/accprofile") {
				return errors.New("path: administrators, API users and their profiles are not changed here")
			}
			return nil
		},
		restore: func(b []byte) (any, bool) {
			var a struct{ Results any }
			if json.Unmarshal(b, &a) != nil {
				return nil, false
			}
			if l, ok := a.Results.([]any); ok {
				if len(l) != 1 {
					return nil, false
				}
				return l[0], true
			}
			return a.Results, a.Results != nil
		},
		alive: func(ctx context.Context) error { _, err := f.get(ctx, "/api/v2/monitor/system/status"); return err },
	}, r, dry)
}

// ---- Infoblox NIOS: WAPI ----

func (n *nios) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	root := "/wapi/" + n.ver + "/"
	return restRaw(ctx, restSpec{
		api: n.api, hdr: jsonHdr(), json: true,
		guard: func(_, p string) error {
			if !strings.HasPrefix(p, root) {
				return fmt.Errorf("path: WAPI is changed below %s", root)
			}
			l := strings.ToLower(p)
			if strings.Contains(l, "fileop") || strings.Contains(l, "adminuser") || strings.Contains(l, "_function=restore") {
				return errors.New("path: file operations, restores and administrator users are not changed here")
			}
			return nil
		},
		restore: func(b []byte) (any, bool) {
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				return nil, false
			}
			delete(m, "_ref")
			return m, true
		},
		alive: func(ctx context.Context) error { _, err := n.get(ctx, "grid"); return err },
	}, r, dry)
}

// ---- F5 BIG-IP: iControl REST ----

func (b *bigip) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	h := jsonHdr()
	if err := bigipBodyCheck(r); err != nil {
		return RawResult{DryRun: dry}, err
	}
	return restRaw(ctx, restSpec{
		api: b.api, hdr: h, json: true,
		guard: func(_, p string) error {
			if !strings.HasPrefix(p, "/mgmt/tm/") {
				return errors.New("path: BIG-IP is changed below /mgmt/tm/")
			}
			if hasSeg(p, "util", "auth", "ucs", "software", "authn", "authz") {
				return errors.New("path: util, auth, ucs and software are not touched here")
			}
			return nil
		},
		restore: func(s []byte) (any, bool) { return s, len(s) > 0 },
		alive:   func(ctx context.Context) error { _, err := b.get(ctx, "/mgmt/tm/sys/version"); return err },
		save: func(ctx context.Context) error {
			_, err := b.api.do(ctx, http.MethodPost, "/mgmt/tm/sys/config", map[string]any{"command": "save"}, h)
			return err
		},
	}, r, dry)
}

// bigipBodyCheck refuses a body that asks for a reboot, a halt or a load.
func bigipBodyCheck(r Raw) error {
	var m map[string]any
	if json.Unmarshal([]byte(r.Body), &m) == nil {
		switch strings.ToLower(str(m["command"])) {
		case "reboot", "halt", "shutdown", "load", "install", "restart":
			return fmt.Errorf("body: the command %q is not sent", str(m["command"]))
		}
	}
	return nil
}

// ---- Technitium: HTTP API ----

// RawChange: Method POST (or GET), Path "/api/zones/records/add", Body "zone=example.com&domain=a.example.com&type=A&ipAddress=1.2.3.4"
// (the query a Technitium call takes).  Technitium has no read of "what was there" that fits every call, so nothing is put back.
func (t *technitium) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	r, err := r.checkREST(http.MethodPost, http.MethodGet)
	if err != nil {
		return res, err
	}
	if !strings.HasPrefix(r.Path, "/api/") || strings.Contains(r.Path, "?") {
		return res, errors.New("path: /api/<call> (the parameters go in the body, as name=value&name=value)")
	}
	l := strings.ToLower(r.Path)
	for _, no := range []string{"/api/user/", "/api/admin/", "/api/settings/restore", "/api/createtoken", "/api/changepassword"} {
		if strings.HasPrefix(l, no) {
			return res, errors.New("path: users, sessions, tokens and restores are not changed here")
		}
	}
	form, err := url.ParseQuery(r.Body)
	if err != nil {
		return res, fmt.Errorf("body: not name=value&name=value: %v", err)
	}
	if dry {
		res.Note = fmt.Sprintf("would send %s %s with %d parameter(s); nothing was changed, and Technitium changes cannot be put back by this program", r.Method, r.Path, len(form))
		return res, nil
	}
	if err := t.login(ctx); err != nil {
		return res, err
	}
	var v any
	if r.Method == http.MethodGet {
		v, err = t.do(ctx, http.MethodGet, r.Path+"?"+form.Encode(), nil)
	} else {
		if len(form) == 0 {
			form = url.Values{}
		}
		v, err = t.do(ctx, http.MethodPost, r.Path, form)
	}
	if err != nil {
		return res, fmt.Errorf("%s %s: %w", r.Method, r.Path, err)
	}
	res.Applied = true
	if v != nil {
		j, _ := json.Marshal(Redact(v))
		res.Answer = rawTrunc(j)
	}
	res.Note = "Technitium keeps its configuration as it is changed; this program cannot put it back"
	return res, nil
}
