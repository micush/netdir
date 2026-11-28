package mcp

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"netdir/internal/devices"
)

// scopeGuard checks a request an MCP tool is about to make for a caller whose devices are limited.
func (c *mcpCtx) scopeGuard(method, path string, body []byte) error {
	sc := devices.ScopeOf(c.s)
	if !sc.Limited() {
		return nil
	}
	p := path
	// a request relayed to another node names its path in the query: look at that one
	for i := 0; i < 3 && strings.HasPrefix(p, "/api/proxy"); i++ {
		u, err := url.Parse(p)
		if err != nil {
			return errors.New("not for a caller limited to some devices")
		}
		p = u.Query().Get("path")
	}
	if u, err := url.Parse(p); err == nil {
		p = u.Path
	}
	for _, x := range devices.ScopeRefusedPrefixes {
		if p == x || strings.HasPrefix(p, x+"/") {
			return errors.New("this key or address is limited to some devices: the configuration, its versions and sign-ins hold every device and every key, so they are not for it")
		}
	}
	switch p {
	case "/api/devices/change", "/api/devices/raw", "/api/devices/capture":
		var a struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(body, &a)
		return c.w.Status.Sup().ScopeWrite(sc, a.Target)
	}
	return nil
}
