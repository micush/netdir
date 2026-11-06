package device

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// RawChange for Observium and Microsoft Entra (Graph), the two REST platforms that had been read-only.  Like every other
// RawChange the caller has checked that the key is read-write; the platform's own permissions (the Observium user or token, the
// Graph application's permissions) decide what the device accepts.

// ---- Observium ----

// RawChange: Method POST, PUT, PATCH or DELETE, Path below /api/v0 (/devices/12/...).  Observium's documented API is read-only, so
// a build or an edition that does not accept the request answers with an error and nothing changes; nothing is put back.
func (o *observium) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	return restRaw(ctx, restSpec{
		api: o.api, hdr: jsonHdr(), json: true,
		wire: func(p string) string { return o.prefix + obsBase + strings.TrimPrefix(p, obsBase) },
		guard: func(_, p string) error {
			if hasSeg(p, "users", "tokens", "token", "login", "logout") {
				return errors.New("path: users, tokens and login are not changed here")
			}
			return nil
		},
		alive: func(ctx context.Context) error {
			_, err := o.get(ctx, "/devices/?fields=device_id&pagesize=1")
			return err
		},
	}, r, dry)
}

// ---- Microsoft Entra: Graph ----

// graphWritable are the first path words a write may start with; graphDenied are the parts of a path that are never written
// (sign-in methods, passwords and keys, roles and consent, policies, and a user's mail and files).
var (
	graphWritable = map[string]bool{"users": true, "devices": true, "groups": true, "organization": true}
	graphDenied   = []string{"authentication", "authenticationMethods", "addPassword", "removePassword", "addKey", "removeKey", "passwordCredentials",
		"keyCredentials", "directoryRoles", "roleManagement", "appRoleAssignments", "oauth2PermissionGrants", "messages", "mailFolders", "drive",
		"drives", "events", "calendar", "calendars", "onenote", "sendMail", "revokeSignInSessions", "resetPassword", "changePassword", "transitiveMemberOf"}
)

// RawChange: Method POST, PATCH, PUT or DELETE, Path below /v1.0 (/devices/{id}, /groups/{id}/members/$ref), Body JSON.  The copy of
// what the path holds is returned as "before"; Graph changes are not put back automatically.
func (e *entra) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	r, err := r.checkREST(http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete)
	if err != nil {
		return res, err
	}
	r.Path = strings.TrimPrefix(r.Path, graphBase)
	pp, _, _ := strings.Cut(r.Path, "?")
	first := strings.SplitN(strings.TrimPrefix(pp, "/"), "/", 2)[0]
	if !graphWritable[first] {
		return res, errors.New("path: Entra is changed at /users, /devices, /groups and /organization (below /v1.0)")
	}
	if hasSeg(pp, graphDenied...) {
		return res, errors.New("path: sign-in methods, passwords, keys, roles, consent, mail and files are not changed here")
	}
	if strings.Contains(strings.ToLower(r.Body), "passwordprofile") {
		return res, errors.New("body: passwords are not set here")
	}
	if r.Method != http.MethodDelete && r.Method != http.MethodPost && strings.TrimSpace(r.Body) == "" {
		return res, fmt.Errorf("body: %s needs one", r.Method)
	}
	if r.Method != http.MethodPost {
		if v, gerr := e.get(ctx, r.Path); gerr == nil && v != nil {
			res.Before = rawTrunc(mustJSON(Redact(v)))
		} else if gerr != nil {
			var se *statusError
			if !errors.As(gerr, &se) || se.Code != http.StatusNotFound {
				return res, fmt.Errorf("the copy of what is there now could not be read (nothing was changed): %w", gerr)
			}
		}
	}
	if dry {
		res.Note = fmt.Sprintf("would send %s %s; nothing was changed, and this program cannot put a Graph change back", r.Method, r.Path)
		return res, nil
	}
	tok, err := e.token(ctx)
	if err != nil {
		return res, err
	}
	hdr := http.Header{"Authorization": {"Bearer " + tok}, "Accept": {"application/json"}}
	if r.Body != "" {
		hdr.Set("Content-Type", "application/json")
	}
	ans, err := e.api.do(ctx, r.Method, graphBase+r.Path, r.Body, hdr)
	if err != nil {
		return res, fmt.Errorf("%s %s: %w", r.Method, r.Path, err)
	}
	res.Applied = true
	res.Answer = rawTrunc(ans)
	res.Note = "Graph keeps the change as made; this program cannot put it back (the 'before' copy shows what was there)"
	return res, nil
}
