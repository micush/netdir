package core

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

const FailWindow = 10 * time.Minute

const LockDuration = 5 * time.Minute

type Session struct {
	User     string    `json:"-"`
	Csrf     string    `json:"-"`
	Created  time.Time `json:"-"`
	Last     time.Time `json:"-"`
	Checked  time.Time `json:"-"` // last group-membership check
	Ip       string    `json:"-"` // the address it signed in from (for the log)
	ReadOnly bool      `json:"-"` // signed in through the read-only group: may look, not change (see readonly.go)
	Ldap     bool      `json:"-"` // signed in with an LDAP directory account (ldap.go): rechecked against the directory, not PAM
	SsoProv  string    `json:"-"` // which provider it signed in with (google or entra)
	Mcp      bool      `json:"-"` // an MCP caller (mcp.go): never handed a device's secrets
	Raw      bool      `json:"-"` // an MCP caller whose privacy level is none: configurations come as the device gives them
	Devs     *DevScope `json:"-"` // the devices an MCP caller may use (devscope.go); nil: all
	Hop      bool      `json:"-"` // handed over by another node (proxy.go): it does not hand a device request on again
	Sso      bool      `json:"-"` // signed in with Google or Entra ID (sso.go): user is an e-mail address, checked against the list of users
}

type FailRec struct {
	Count    int       `json:"-"`
	Inflight int       `json:"-"` // login attempts that passed the lockout check and have not finished yet
	First    time.Time `json:"-"`
	Locked   time.Time `json:"-"`
}

// ── helpers ──────────────────────────────────────────────────────────────────

func WriteJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	json.NewEncoder(rw).Encode(v)
}

func JsonError(rw http.ResponseWriter, code int, msg string) {
	WriteJSON(rw, code, map[string]any{"ok": false, "error": msg})
}

func ReadJSON(rw http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, limit))
	if err != nil {
		JsonError(rw, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		JsonError(rw, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func ClientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
