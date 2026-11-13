package device

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The content log: every request a REST driver sends to a device and every reply, one JSON line each, in
// ContentLogDir/<device name>.log.  It is OFF unless the device has the option content_log=on, and it keeps a bounded amount:
//
//	content_log=on|off        default off
//	content_log_mb=N          the most disk the device's log may use, 1 to 1000 (default 20): when the file reaches half of it, it
//	                          becomes <name>.log.1 and the older .log.1 is deleted, so the oldest entries go first
//	content_log_entry_kb=N    the most of one request body or of one reply that is written, 1 to 1024 (default 64); the rest is cut
//
// The line holds the time, the device, the method, the path with its query, the status, the time taken in ms, the request body, the
// reply body and any transport error.  Never logged: the headers (so no password, token or session cookie), and the bodies of
// anything that signs in or out (a path with login, authenticate, token, session or password in it), which are replaced by a
// note.  What is written passes through Redact and RedactText (secrets found by name; JSON is scrubbed value by value and written again compactly).  The rest is as the device sent it, unmasked, so the
// file is private (mode 0600, directory 0700): it is for the person who runs the gateway, not for MCP callers.
// Only drivers that talk through apiClient (the REST ones) are logged; SNMP, LDAP and the like are not.

// ContentLogDir is the directory of the content logs; "" turns the whole feature off (a test, a host with no state directory).
var ContentLogDir string

const (
	clDefaultMB = 20
	clDefaultKB = 64
)

var clSignInRE = regexp.MustCompile(`(?i)login|logout|authenticate|/auth(/|\?|$)|token|session|password`)

type contentLog struct {
	mu      sync.Mutex
	name    string
	path    string
	half    int64 // rotate at this size
	entryKB int
	f       *os.File
	size    int64
}

var (
	clMu   sync.Mutex
	clLogs = map[string]*contentLog{}
)

// contentLogFor returns the log a device's options ask for, or nil when it is off.
func contentLogFor(d Device) *contentLog {
	if ContentLogDir == "" || !strings.EqualFold(strings.TrimSpace(d.Options["content_log"]), "on") || !nameRE.MatchString(d.Name) {
		return nil
	}
	mb, kb := clDefaultMB, clDefaultKB
	if v, err := strconv.Atoi(strings.TrimSpace(d.Options["content_log_mb"])); err == nil && v >= 1 && v <= 1000 {
		mb = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(d.Options["content_log_entry_kb"])); err == nil && v >= 1 && v <= 1024 {
		kb = v
	}
	clMu.Lock()
	defer clMu.Unlock()
	key := ContentLogDir + "\x00" + d.Name
	l := clLogs[key]
	if l == nil {
		l = &contentLog{name: d.Name, path: filepath.Join(ContentLogDir, d.Name+".log")}
		clLogs[key] = l
	}
	l.mu.Lock()
	l.half, l.entryKB = int64(mb)<<20/2, kb // a changed option applies from the next entry
	l.mu.Unlock()
	return l
}

func (l *contentLog) open() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *contentLog) cut(b []byte, signIn bool) string {
	if signIn {
		return "(not logged: sign-in)"
	}
	s := clScrub(b)
	if max := l.entryKB << 10; len(s) > max {
		s = s[:max] + fmt.Sprintf("…(%d more bytes)", len(s)-max)
	}
	return s
}

// clScrub hides secrets in a body.  JSON is scrubbed value by value (RedactText over the text of a JSON line would take the rest
// of the line, and with it the rest of the reply), and written again compactly; anything else goes through RedactText.
func clScrub(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		if out, err := json.Marshal(obsScrub(Redact(v))); err == nil {
			return string(out)
		}
	}
	return RedactText(string(b))
}

// record writes one request and its reply.  A failure to write is not the request's failure: it is dropped.
func (l *contentLog) record(start time.Time, method, path string, reqBody []byte, status int, reply []byte, err error) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	signIn := clSignInRE.MatchString(path)
	e := map[string]any{"t": start.UTC().Format(time.RFC3339Nano), "device": l.name, "method": method, "path": RedactText(path),
		"status": status, "ms": time.Since(start).Milliseconds()}
	if len(reqBody) > 0 {
		e["request"] = l.cut(reqBody, signIn)
	}
	if len(reply) > 0 {
		e["reply"] = l.cut(reply, signIn)
	}
	if err != nil {
		e["error"] = RedactText(err.Error())
	}
	line, _ := json.Marshal(e)
	line = append(line, '\n')
	if l.f == nil && l.open() != nil {
		return
	}
	if l.size > 0 && l.size+int64(len(line)) > l.half {
		l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".1") // replaces the older one
		if l.open() != nil {
			return
		}
	}
	if n, werr := l.f.Write(line); werr == nil {
		l.size += int64(n)
	}
}

// ContentLogPath is where the content log of a device is (the file may not exist: the option is off, or nothing was sent yet).
func ContentLogPath(name string) string {
	if ContentLogDir == "" || !nameRE.MatchString(name) {
		return ""
	}
	return filepath.Join(ContentLogDir, name+".log")
}
