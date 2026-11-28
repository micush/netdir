package core

// The MCP content log: everything that goes into the MCP endpoint and everything that comes out of it, one JSON line per HTTP
// request, in <state dir>/mcp-content.log.  It is one log for the whole endpoint (not per device), it is OFF unless
// settings.mcp_log is on (Configure ▸ MCP ▸ Content log), and it keeps a bounded amount:
//
//	mcp_log           true or false (default false)
//	mcp_log_mb        the most disk the log may use, 1 to 1000 (default 50): at half of it the file becomes mcp-content.log.1 and the
//	                  older .log.1 is deleted, so the oldest entries go first
//	mcp_log_entry_kb  the most of one request or of one reply that is written, 1 to 8192 (default 256); the rest is cut and the cut is marked
//
// A line holds: t (the time), from (the caller's address), who (its key name and address), access (ro or rw), status (the HTTP
// status), ms (the time taken), request (the JSON-RPC message as it was sent, with secrets hidden: mcpRedact) and reply (the
// answer exactly as it was sent to the caller, so it is already masked to the caller's privacy level), and note when something was
// cut.  A request that is refused (no key, an address that is not allowed, a wrong method) is logged too, with its status and
// reply but no request, since nothing of it was read.  Never logged: the Authorization header, so no key.  The file is mode 0600
// and holds what callers asked and were told, so it is for the person who runs the gateway.  Each node writes its own file:
// the log is not shared across a cluster and is not part of a backup.

const (
	mcpLogDefaultMB = 50
	mcpLogDefaultKB = 256
	mcpLogMaxMB     = 1000
	mcpLogMaxKB     = 8192
)

func (s Settings) McpLogLimits() (mb, kb int) {
	mb, kb = mcpLogDefaultMB, mcpLogDefaultKB
	if s.MCPLogMB > 0 {
		mb = s.MCPLogMB
	}
	if s.MCPLogEntryKB > 0 {
		kb = s.MCPLogEntryKB
	}
	return
}
