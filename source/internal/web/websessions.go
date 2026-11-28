package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"netdir/internal/core"
)

// sessKey is what a cookie value is filed under, in memory and on disk.
func SessKey(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

type sessionRec struct {
	Key     string `json:"k"`
	User    string `json:"u"`
	CSRF    string `json:"c"`
	Created int64  `json:"cr"`
	Last    int64  `json:"l"`
	RO      bool   `json:"ro,omitempty"` // a read-only account
	IP      string `json:"ip,omitempty"` // where it signed in from
	SSO     bool   `json:"sso,omitempty"`
	SSOProv string `json:"sso_provider,omitempty"`
	LDAP    bool   `json:"ldap,omitempty"`
}

// loadSessions restores the sessions saved by the last run; whatever has run out is dropped.
func (w *WebServer) loadSessions() {
	if w.StateDir == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(w.StateDir, core.SessionsFile))
	if err != nil {
		return
	}
	var recs []sessionRec
	if json.Unmarshal(b, &recs) != nil {
		return
	}
	now := time.Now()
	n := 0
	w.Mu.Lock()
	for _, r := range recs {
		created, last := time.Unix(r.Created, 0), time.Unix(r.Last, 0)
		if r.Key == "" || r.User == "" || r.CSRF == "" || now.Sub(created) > sessionMaxAge || now.Sub(last) > w.Policy.Load().SessionIdle() {
			continue
		}
		// checked is left at zero: the group is looked at again with the first request
		w.Sessions[r.Key] = &core.Session{User: r.User, Csrf: r.CSRF, Created: created, Last: last, ReadOnly: r.RO, Ip: r.IP, Sso: r.SSO, SsoProv: r.SSOProv, Ldap: r.LDAP}
		n++
	}
	w.Mu.Unlock()
	if n > 0 {
		core.Infof("web: %d session(s) restored from the last run", n)
	}
}

// saveSessions writes the live sessions.  A failure is only logged: the sessions then end with the process, as before.
func (w *WebServer) saveSessions() {
	if w.StateDir == "" || w.noSave.Load() {
		return
	}
	w.Mu.Lock()
	recs := make([]sessionRec, 0, len(w.Sessions))
	for k, s := range w.Sessions {
		recs = append(recs, sessionRec{Key: k, User: s.User, CSRF: s.Csrf, Created: s.Created.Unix(), Last: s.Last.Unix(), RO: s.ReadOnly, IP: s.Ip, SSO: s.Sso, SSOProv: s.SsoProv, LDAP: s.Ldap})
	}
	w.Mu.Unlock()
	b, _ := json.Marshal(recs)
	final := filepath.Join(w.StateDir, core.SessionsFile)
	if len(recs) == 0 {
		os.Remove(final)
		return
	}
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		if err = os.Rename(tmp, final); err != nil {
			os.Remove(tmp)
			core.Warnf("web: cannot save the sessions: %v", err)
		}
	} else {
		core.Warnf("web: cannot save the sessions: %v", err)
	}
}
