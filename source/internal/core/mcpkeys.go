package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// MCP keys: besides the address list (mcp_acl), a caller may present a key, so an assistant on a laptop whose address
// changes (DHCP, VPN, Wi-Fi) can still connect.  The key goes in the request header "Authorization: Bearer KEY".  A
// valid key gives its access (ro or rw) from any address; the address list still applies too, and the caller gets the
// higher of the two.  A key that is sent but matches none is refused outright (401), never quietly ignored, so a typo
// shows at once.
//
// The key is kept in the configuration beside its SHA-256 hash, as the gateway keys and the device logins are (so it
// is in the cluster and the configuration history too, is never shown to an MCP caller or a read-only account, and
// can be shown again from Configure ▸ MCP ▸ Show key).  The hash is what a request is checked against.  A
// key made before the key was kept has only a hash and cannot be shown: Replace key makes it a new one.  A new key may
// be given in "key" (the GUI does this, as may a hand-edited file); the check works out "hash" from it.

const (
	mcpKeysMax    = 32
	mcpKeyMinLen  = 32 // a key given by hand must be at least this long
	mcpKeyNameMax = 40
)

// MCPKey is one key that may use the MCP endpoint.
type MCPKey struct {
	Name    string `json:"name"`              // who or what holds it ("laptop", "claude-ops"); the caller is logged as mcp:NAME@ADDRESS
	Access  string `json:"access"`            // "ro" or "rw"
	Privacy string `json:"privacy,omitempty"` // "none", "standard" or "strict"; empty: the default level (Configure ▸ Privacy)
	Hash    string `json:"hash,omitempty"`    // "sha256:" and the hex hash of the key (worked out from Key when there is one)
	Key     string `json:"key,omitempty"`     // the key itself; empty for a key made before it was kept
	Created int64  `json:"created,omitempty"` // unix time the key was added
	// Devices is what the key may reach: device names and tag:TAG, or "none"; empty is all (devscope.go).
	Devices []string `json:"devices,omitempty"`
	// Disabled keeps the key in the list and lets it do nothing: the caller is refused like one with an unknown key (right-click ▸ Disable).
	Disabled bool `json:"disabled,omitempty"`
	// Expires is the unix time from which the key does nothing (0: never).  It stays in the list, shown as expired, until it is deleted.
	Expires int64 `json:"expires,omitempty"`
	// Notes says what the key is for ("claude on Mike's laptop, for the Axway audit"): up to mcpNoteMax characters, one line.  It changes nothing.
	Notes string `json:"notes,omitempty"`
}

// mcpNow is the clock of the expiry checks (a variable for the tests).
var McpNow = time.Now

// Expired says whether the key's time has passed.
func (k MCPKey) Expired() bool { return k.Expires > 0 && McpNow().Unix() >= k.Expires }

func McpKeyHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(h[:])
}

// normMCPKeys checks the keys, turns a new key into its hash, and writes the access the same way ("ro" when not given).
func NormMCPKeys(list []MCPKey) ([]MCPKey, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) > mcpKeysMax {
		return nil, fmt.Errorf("mcp: at most %d keys", mcpKeysMax)
	}
	out := make([]MCPKey, 0, len(list))
	names, hashes := map[string]bool{}, map[string]bool{}
	for _, k := range list {
		k.Name = strings.TrimSpace(k.Name)
		if k.Name == "" {
			return nil, errors.New("mcp: every key needs a name (who or what holds it)")
		}
		if len(k.Name) > mcpKeyNameMax || strings.IndexFunc(k.Name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r))
		}) >= 0 {
			return nil, fmt.Errorf("mcp: key name %q: up to %d letters, digits, dots, dashes and underscores", k.Name, mcpKeyNameMax)
		}
		if names[strings.ToLower(k.Name)] {
			return nil, fmt.Errorf("mcp: two keys are named %q", k.Name)
		}
		names[strings.ToLower(k.Name)] = true
		switch strings.ToLower(strings.TrimSpace(k.Access)) {
		case "", "ro", "read-only", "readonly":
			k.Access = "ro"
		case "rw", "read-write", "readwrite":
			k.Access = "rw"
		default:
			return nil, fmt.Errorf("mcp: key %q: the access is ro or rw", k.Name)
		}
		k.Notes = strings.Join(strings.Fields(k.Notes), " ")
		if err := checkNote(k.Notes); err != nil {
			return nil, fmt.Errorf("mcp: key %q: %w", k.Name, err)
		}
		var derr error
		if k.Devices, derr = NormDevices(k.Devices); derr != nil {
			return nil, fmt.Errorf("mcp: key %q: %w", k.Name, derr)
		}
		if k.Expires < 0 || k.Expires > 253402300799 {
			return nil, fmt.Errorf("mcp: key %q: the expiry is a time (unix seconds) or empty for never", k.Name)
		}
		var okLevel bool
		if k.Privacy, okLevel = normLevel(k.Privacy); !okLevel {
			return nil, fmt.Errorf("mcp: key %q: the privacy level is none, standard or strict", k.Name)
		}
		if k.Key != "" {
			if strings.TrimSpace(k.Key) != k.Key || len(k.Key) < mcpKeyMinLen {
				return nil, fmt.Errorf("mcp: key %q: a key is at least %d characters, without spaces (Add key makes one)", k.Name, mcpKeyMinLen)
			}
			k.Hash = McpKeyHash(k.Key)
			if k.Created == 0 {
				k.Created = time.Now().Unix()
			}
		}
		h, ok := strings.CutPrefix(strings.ToLower(k.Hash), "sha256:")
		if b, err := hex.DecodeString(h); !ok || err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("mcp: key %q has no key or hash: add it again", k.Name)
		}
		k.Hash = "sha256:" + h
		if hashes[k.Hash] {
			return nil, fmt.Errorf("mcp: key %q is the same key as another one", k.Name)
		}
		hashes[k.Hash] = true
		out = append(out, k)
	}
	return out, nil
}

// inNets reports whether a is in any of nets.
func inNets(nets []netip.Prefix, a netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
