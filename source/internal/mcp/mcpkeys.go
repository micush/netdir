package mcp

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"netdir/internal/core"
)

// mcpKeyExpired says that the key presented is one of the list but its time has passed.
func mcpKeyExpired(keys []core.MCPKey, presented string) bool {
	got := core.McpKeyHash(presented)
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(k.Hash)) == 1 && k.Expired() {
			return true
		}
	}
	return false
}

// mcpKeyAccess finds the key a caller presented: its name and access, or "" when it matches none.  Every hash is
// compared, in constant time, so the answer takes as long whichever key (if any) matches.
func McpKeyAccess(keys []core.MCPKey, presented string) (name, access string) {
	got := core.McpKeyHash(presented)
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(k.Hash)) == 1 && name == "" && !k.Disabled && !k.Expired() {
			name, access = k.Name, k.Access
		}
	}
	return name, access
}

// mcpKeyDevices is the devices of the key with this name (nil: all of them).
func mcpKeyDevices(keys []core.MCPKey, name string) []string {
	for _, k := range keys {
		if k.Name == name {
			return k.Devices
		}
	}
	return nil
}

// mcpKeyPrivacy is the privacy level of the key with this name ("" when it has none of its own).
func mcpKeyPrivacy(keys []core.MCPKey, name string) string {
	for _, k := range keys {
		if k.Name == name {
			return k.Privacy
		}
	}
	return ""
}

// mcpBearer is the key in "Authorization: Bearer KEY"; ok is false when the header is there but not of that form.
func mcpBearer(r *http.Request) (key string, ok bool) {
	a := strings.TrimSpace(r.Header.Get("Authorization"))
	if a == "" {
		return "", true
	}
	scheme, key, found := strings.Cut(a, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	key = strings.TrimSpace(key)
	return key, key != ""
}

// mcpBadKeyLog says once a minute per address that a wrong key was sent, so a client retrying in a loop cannot fill the log.
var mcpBadKeyLog = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

func mcpWarnBadKey(from string) {
	l := &mcpBadKeyLog
	l.Lock()
	defer l.Unlock()
	if time.Since(l.at[from]) < time.Minute {
		return
	}
	if len(l.at) > 1000 {
		l.at = map[string]time.Time{}
	}
	l.at[from] = time.Now()
	core.Warnf("mcp: %s sent a key that matches none (Configure ▸ MCP ▸ Keys); refused", from)
}

func maxAccess(a, b string) string {
	if a == "rw" || b == "rw" {
		return "rw"
	}
	if a == "ro" || b == "ro" {
		return "ro"
	}
	return ""
}
