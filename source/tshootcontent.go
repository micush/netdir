package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// The MCP content log in the troubleshooting bundle (netdir/mcp-content.log): the newest requests and replies, the same one JSON line
// each as in <state dir>/mcp-content.log (contentlog.go), so that a ticket shows what a caller asked and was told.  What is in the file
// was already filtered once, the way the caller saw it (secrets hidden, the caller's privacy level applied); the bundle then removes
// secrets the way it does for everything else (redactJSON, redactText, over every key and every string, including the text of a reply).
// At most tshootContentMax bytes of the newest entries are read, and the bundle's size fit (TshootNode) cuts the older half again
// when the bundle is still too large for the cluster channel.

const tshootContentMax = 4 << 20

const (
	tshootContentOff   = "{\"note\": \"the content log is off: Configure > MCP > Log all MCP requests and replies\"}\n"
	tshootContentEmpty = "{\"note\": \"the content log is on and has no entries yet\"}\n"
)

// tshootTail is the last max bytes of a file, from the start of a line.
func tshootTail(path string, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	start := st.Size() - max
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	if n, _ := f.ReadAt(buf, start); n < len(buf) {
		buf = buf[:n]
	}
	if start > 0 { // began in the middle of a line: drop it
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			return nil
		}
	}
	return buf
}

// redactStrings runs redactText over every string of a decoded JSON value, however deep.
func redactStrings(v any) (any, int) {
	n := 0
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				t[k] = walk(val)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case string:
			s, c := redactText(t)
			n += c
			return s
		}
		return x
	}
	return walk(v), n
}

// tshootScrubLine removes secrets from one line of the log; a line that is not JSON is cleaned as text.
func tshootScrubLine(line []byte) ([]byte, int) {
	var v any
	if json.Unmarshal(line, &v) != nil {
		s, n := redactText(string(line))
		return []byte(s), n
	}
	v, n1 := redactJSON(v)
	v, n2 := redactStrings(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("{\"note\": \"a line of the log could not be cleaned and was left out\"}"), n1 + n2
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), n1 + n2
}

// tshootContentLog is the bundle's copy of the content log in dir: the newest entries, cleaned, oldest first.
func tshootContentLog(dir string, on bool) ([]byte, int) {
	cur := tshootTail(filepath.Join(dir, "mcp-content.log"), tshootContentMax)
	if room := tshootContentMax - int64(len(cur)); room > 0 {
		cur = append(tshootTail(filepath.Join(dir, "mcp-content.log.1"), room), cur...)
	}
	if len(bytes.TrimSpace(cur)) == 0 {
		if on {
			return []byte(tshootContentEmpty), 0
		}
		return []byte(tshootContentOff), 0
	}
	var out bytes.Buffer
	removed := 0
	for _, l := range strings.Split(strings.TrimRight(string(cur), "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		c, n := tshootScrubLine([]byte(l))
		removed += n
		out.Write(c)
		out.WriteByte('\n')
	}
	return out.Bytes(), removed
}

// tshootHalve drops the older half of a log of lines (the bundle was too large for the cluster channel) and says so in a first line.
func tshootHalve(b []byte) []byte {
	rest := b[len(b)/2:]
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	}
	return append([]byte("{\"note\": \"older entries cut to fit\"}\n"), rest...)
}
