package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StatusServer answers JSON-line commands on a Unix socket:
//
//	{"cmd":"snapshot"}   neighbor/gateway table
//	{"cmd":"assert-agc"} directed failover onto this node
//
// Anything that changes state or exposes configuration (assert-agc and every
// management command such as versions.restore or tls.install) is accepted
// only from root (SO_PEERCRED); the read-only snapshot views stay open to
// local users as before.
type StatusServer struct {
	path   string
	sup    *Supervisor
	mg     *Mgmt
	alerts *AlertEngine // /metrics counts the open alerts
	l      net.Listener
	up     *upTracker
	stop   chan struct{}
}

func NewStatusServer(path string, sup *Supervisor) *StatusServer {
	return &StatusServer{path: path, sup: sup, up: newUpTracker()}
}

// peerCred returns the uid and a printable name of the process on the other
// end of a unix connection.
func peerCred(c net.Conn) (uint32, string, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, "", errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, "", err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, "", err
	}
	if serr != nil {
		return 0, "", serr
	}
	name := "uid " + strconv.Itoa(int(cred.Uid))
	if u, err := user.LookupId(name[4:]); err == nil {
		name = u.Username
	}
	return cred.Uid, "cli:" + name, nil
}

// privileged reports whether the connection may run state-changing commands.
func privileged(uid uint32) bool { return uid == 0 || int(uid) == os.Geteuid() }

func (s *StatusServer) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	os.Remove(s.path)
	l, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	s.l = l
	s.stop = make(chan struct{})
	go s.sampleUptime(s.stop)
	go hoststats.Run(s.stop)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	debugf("Status socket listening at %s", s.path)
	return nil
}

// sampleUptime looks at the topology picture every few seconds so the uptimes notice an
// outage even when nobody has the page open.
func (s *StatusServer) sampleUptime(stop chan struct{}) {
	t := time.NewTicker(upSampleEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.canvasGroups() // notes the uptimes
		}
	}
}

func (s *StatusServer) Stop() {
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	if s.l != nil {
		s.l.Close()
		os.Remove(s.path)
	}
}

func (s *StatusServer) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // uploads can be large
	line, err := bufio.NewReaderSize(c, 1<<20).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	c.SetDeadline(time.Now().Add(150 * time.Second)) // joins/syncs talk to peers
	var req struct {
		Cmd  string          `json:"cmd"`
		Args json.RawMessage `json:"args"`
	}
	if json.Unmarshal(line, &req) != nil || req.Cmd == "" {
		req.Cmd = "snapshot"
	}
	uid, actor, credErr := peerCred(c)
	allowed := credErr == nil && privileged(uid)
	var res map[string]any
	switch req.Cmd {
	case "snapshot":
		res = map[string]any{"ok": true, "data": s.snapshot(), "names": s.ipNames()}
	case "canvas":
		res = s.canvasView()
	case "assert-agc":
		if !allowed {
			res = denied()
		} else if s.mg != nil && s.mg.pausedFn != nil && s.mg.pausedFn() {
			res = map[string]any{"ok": false, "error": "this node is paused: resume it before making it the gateway controller"}
		} else {
			res = s.assertAGC()
		}
	default:
		switch {
		case !strings.Contains(req.Cmd, "."):
			res = map[string]any{"ok": false, "error": "Unknown command: " + req.Cmd}
		case !allowed:
			res = denied()
		case s.mg == nil:
			res = map[string]any{"ok": false, "error": "management is not available"}
		default:
			data, err := s.mg.Op(req.Cmd, req.Args, actor)
			if err != nil {
				res = map[string]any{"ok": false, "error": err.Error(), "data": data}
			} else {
				res = map[string]any{"ok": true, "data": data}
			}
		}
	}
	b, _ := json.Marshal(res)
	c.Write(append(b, '\n'))
}

func (s *StatusServer) snapshot() []SnapshotRow {
	rows := []SnapshotRow{}
	for _, e := range s.sup.engineList() {
		rows = append(rows, e.snapshot()...)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.GroupID != b.GroupID {
			return a.GroupID < b.GroupID
		}
		if a.AF != b.AF {
			return a.AF < b.AF
		}
		return a.PeerIP < b.PeerIP
	})
	return rows
}

func (s *StatusServer) assertAGC() map[string]any {
	var msgs []string
	for _, e := range s.sup.engineList() {
		e.mu.Lock()
		msgs = append(msgs, e.assertAGCLocked())
		e.mu.Unlock()
	}
	if len(msgs) == 0 {
		return map[string]any{"ok": false, "error": "No engines running"}
	}
	return map[string]any{"ok": true, "messages": msgs}
}

// ipNames maps the addresses of the cluster's nodes (as the Gateways page lists them) to the nodes' names.
func (s *StatusServer) ipNames() map[string]string {
	if s.mg == nil || s.mg.cl == nil {
		host, _ := os.Hostname()
		out := map[string]string{}
		for _, r := range s.snapshot() {
			if r.Local && r.PeerIP != "" {
				out[normIP(r.PeerIP)] = host
			}
		}
		return out
	}
	return nodeNamesByIP(s.mg.cl.View().Peers)
}

func denied() map[string]any {
	return map[string]any{"ok": false, "error": "permission denied: this command must be run as root (try sudo)"}
}

// statusRequest is the CLI side.
func statusRequest(path string, cmd map[string]any) (map[string]any, error) {
	return statusRequestTimeout(path, cmd, 5*time.Second)
}

func statusRequestTimeout(path string, cmd map[string]any, timeout time.Duration) (map[string]any, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("netdir is not running (status socket not found)")
		}
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	b, _ := json.Marshal(cmd)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	var res map[string]any
	if err := json.NewDecoder(c).Decode(&res); err != nil {
		return nil, err
	}
	return res, nil
}
