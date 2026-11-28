package core

type ProxyReq struct {
	User   string `json:"user"`
	Method string `json:"method"`
	Path   string `json:"path"` // /api/...?query
	CT     string `json:"ct,omitempty"`
	Body   []byte `json:"body,omitempty"`
	RO     bool   `json:"ro,omitempty"`  // the user is on a read-only account: the other node holds the line too
	MCP    bool   `json:"mcp,omitempty"` // an MCP caller: never handed a device's secrets (devices.go sends a device request to the node that checks it)
	Raw    bool   `json:"raw,omitempty"` // an MCP caller whose privacy level is none
}

type ProxyResp struct {
	Status int    `json:"status"`
	CT     string `json:"ct,omitempty"`
	Disp   string `json:"disp,omitempty"`
	Body   []byte `json:"body,omitempty"`
}
