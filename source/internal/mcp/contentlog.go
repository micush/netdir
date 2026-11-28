package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"netdir/internal/core"
)

type mcpContentLogger struct {
	Mu    sync.Mutex `json:"-"`
	dir   string
	Rf    *core.RotatingFile `json:"-"`
	maxMB int
}

var McpContent = &mcpContentLogger{}

// startContentLog says where the log is written (the state directory).  Nothing is written while the setting is off.
func StartContentLog(stateDir string) {
	McpContent.Mu.Lock()
	McpContent.dir = stateDir
	McpContent.Mu.Unlock()
}

// write appends one line, opening the file (or opening it again when the size limit has changed).  A failure is dropped: the log
// never breaks a request.
func (l *mcpContentLogger) write(mb int, line []byte) {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	if l.dir == "" {
		return
	}
	if l.Rf == nil || l.maxMB != mb {
		if err := os.MkdirAll(l.dir, 0o700); err != nil {
			return
		}
		rf, err := core.OpenRotatingFile(filepath.Join(l.dir, "mcp-content.log"), int64(mb)<<20/2, 1)
		if err != nil {
			return
		}
		if l.Rf != nil && l.Rf.F != nil {
			l.Rf.F.Close()
		}
		l.Rf, l.maxMB = rf, mb
	}
	l.Rf.Write(line)
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
func (c *mcpCapture) record(set core.Settings, r *http.Request, started time.Time, q *mcpLogReq) {
	mb, kb := set.McpLogLimits()
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
	McpContent.write(mb, append(line, '\n'))
}
