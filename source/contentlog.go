package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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

type mcpContentLogger struct {
	mu    sync.Mutex
	dir   string
	rf    *rotatingFile
	maxMB int
}

var mcpContent = &mcpContentLogger{}

// startContentLog says where the log is written (the state directory).  Nothing is written while the setting is off.
func startContentLog(stateDir string) {
	mcpContent.mu.Lock()
	mcpContent.dir = stateDir
	mcpContent.mu.Unlock()
}

func (s Settings) mcpLogLimits() (mb, kb int) {
	mb, kb = mcpLogDefaultMB, mcpLogDefaultKB
	if s.MCPLogMB > 0 {
		mb = s.MCPLogMB
	}
	if s.MCPLogEntryKB > 0 {
		kb = s.MCPLogEntryKB
	}
	return
}

// write appends one line, opening the file (or opening it again when the size limit has changed).  A failure is dropped: the log
// never breaks a request.
func (l *mcpContentLogger) write(mb int, line []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dir == "" {
		return
	}
	if l.rf == nil || l.maxMB != mb {
		if err := os.MkdirAll(l.dir, 0o700); err != nil {
			return
		}
		rf, err := openRotatingFile(filepath.Join(l.dir, "mcp-content.log"), int64(mb)<<20/2, 1)
		if err != nil {
			return
		}
		if l.rf != nil && l.rf.f != nil {
			l.rf.f.Close()
		}
		l.rf, l.maxMB = rf, mb
	}
	l.rf.Write(line)
}

// mcpCapture wraps the response writer of a request to keep what is written to it (up to the entry limit) and its status.
type mcpCapture struct {
	http.ResponseWriter
	code  int
	buf   bytes.Buffer
	limit int
	total int
}

func (c *mcpCapture) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *mcpCapture) Write(p []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	c.total += len(p)
	if room := c.limit - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return c.ResponseWriter.Write(p)
}

// mcpLogReq is what is known of a request while it is handled; handleMCP fills it in and the deferred record() writes it.
type mcpLogReq struct {
	from, who, access string
	body              []byte
}

// scrubRequest writes the JSON-RPC message with its secrets hidden (what a caller sends in a change can be one).
func mcpScrubRequest(body []byte) (string, bool) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return "(not JSON, not logged)", true
	}
	b, err := json.Marshal(mcpRedact(v))
	if err != nil {
		return "(not logged)", true
	}
	return string(b), false
}

func mcpCut(s string, max int) (string, int) {
	if len(s) <= max {
		return s, 0
	}
	cut := max
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut], len(s) - cut
}

// mcpAsJSON is a logged body as JSON, so that jq can read into it, when it is whole and is JSON; else as text.
func mcpAsJSON(s string, cut bool) any {
	if !cut && json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	return s
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// record writes the line of one request.
func (c *mcpCapture) record(set Settings, r *http.Request, started time.Time, q *mcpLogReq) {
	mb, kb := set.mcpLogLimits()
	max := kb << 10
	e := map[string]any{"t": started.UTC().Format(time.RFC3339Nano), "from": q.from, "who": q.who, "access": q.access,
		"method": r.Method, "status": c.code, "ms": time.Since(started).Milliseconds()}
	var notes []string
	if len(q.body) > 0 {
		s, _ := mcpScrubRequest(q.body)
		s, more := mcpCut(s, max)
		if more > 0 {
			notes = append(notes, fmt.Sprintf("request cut: %d more bytes", more))
		}
		e["request"] = mcpAsJSON(s, more > 0)
	}
	if c.buf.Len() > 0 {
		s, _ := mcpCut(c.buf.String(), max)
		if c.total > len(s) {
			notes = append(notes, fmt.Sprintf("reply cut: %d more bytes", c.total-len(s)))
		}
		e["reply"] = mcpAsJSON(s, c.total > len(s))
	}
	if len(notes) > 0 {
		e["note"] = notes
	}
	line, _ := json.Marshal(e)
	mcpContent.write(mb, append(line, '\n'))
}
