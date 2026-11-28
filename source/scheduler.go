package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"netdir/internal/core"
)

const schedGrace = 15 * time.Second

const schedTick = 5 * time.Second

const schedHistoryMax = 300

const schedOutputMax = 4096

// schedOffset is where in the window this node runs the occurrence: the same every time it is asked, and different
// from node to node and occurrence to occurrence.
func schedOffset(nodeID, taskID string, base time.Time, windowSec int) time.Duration {
	if windowSec <= 0 {
		return 0
	}
	h := sha256.Sum256([]byte(nodeID + "|" + taskID + "|" + strconv.FormatInt(base.Unix(), 10)))
	return time.Duration(binary.BigEndian.Uint64(h[:8])%uint64(windowSec+1)) * time.Second
}

// ── what ran ─────────────────────────────────────────────────────────────────

// SchedRun is one entry of this node's history.
type SchedRun struct {
	Task   string `json:"task"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Base   int64  `json:"base"`  // the scheduled time it was for (unix)
	Start  int64  `json:"start"` // when it began (unix)
	End    int64  `json:"end,omitempty"`
	Status string `json:"status"` // running, ok, failed, skipped
	Output string `json:"output,omitempty"`
}

type schedState struct {
	Last    map[string]int64 `json:"last"` // task id -> the scheduled time (unix) last dealt with
	History []SchedRun       `json:"history"`
	Queue   []schedQueued    `json:"queue,omitempty"` // jobs waiting for the one that is running
}

// Scheduler runs this node's part of the tasks.
type Scheduler struct {
	m       *Mgmt
	path    string
	mu      sync.Mutex
	tasks   []core.SchedTask
	st      schedState
	running map[string]bool
	node    string                   // this node, as of the last Tick
	slots   map[string]time.Duration // staggered places already worked out (schedstagger.go)
	now     func() time.Time         // replaceable in tests
	// act runs a built-in action (replaceable in tests)
	act func(action, actor string) (string, error)
}

func newScheduler(m *Mgmt, stateDir string) *Scheduler {
	s := &Scheduler{m: m, path: filepath.Join(stateDir, "scheduler.json"), running: map[string]bool{}, now: time.Now}
	s.st.Last = map[string]int64{}
	if b, err := os.ReadFile(s.path); err == nil {
		var st schedState
		if json.Unmarshal(b, &st) == nil {
			s.st = st
			if s.st.Last == nil {
				s.st.Last = map[string]int64{}
			}
		}
	}
	for i := range s.st.History { // a run that was going when the daemon stopped did not finish
		if s.st.History[i].Status == "running" {
			s.st.History[i].Status, s.st.History[i].Output = "failed", "interrupted: the daemon stopped or restarted while it ran"
		}
	}
	s.act = s.builtin
	return s
}

// SetTasks is called with the task list every time a configuration has been loaded.
func (s *Scheduler) SetTasks(l []core.SchedTask) {
	s.mu.Lock()
	s.tasks = append([]core.SchedTask(nil), l...)
	s.slots = nil
	s.mu.Unlock()
}

func (s *Scheduler) saveLocked() {
	b, _ := json.Marshal(s.st)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		if err := os.Rename(tmp, s.path); err != nil {
			core.Warnf("scheduler: saving the history: %v", err)
		}
	}
}

func (s *Scheduler) addLocked(r SchedRun) {
	s.st.History = append(s.st.History, r)
	if n := len(s.st.History); n > schedHistoryMax {
		s.st.History = append([]SchedRun(nil), s.st.History[n-schedHistoryMax:]...)
	}
}

// Run is the loop.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(schedTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(core.LocalNodeID())
		}
	}
}

// Tick starts what is due for the node now.
func (s *Scheduler) Tick(nodeID string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.node = nodeID
	known := map[string]bool{}
	dirty := false
	for _, t := range s.tasks {
		known[t.ID] = true
		if t.Disabled || !t.AppliesTo(nodeID) {
			delete(s.st.Last, t.ID) // a task switched on again starts from then, not from what it missed
			continue
		}
		last, seen := s.st.Last[t.ID]
		if !seen { // new here: nothing before this moment is owed
			s.st.Last[t.ID] = now.Unix()
			dirty = true
			continue
		}
		from := time.Unix(last, 0).Add(time.Second)
		if lim := now.Add(-31 * 24 * time.Hour); from.Before(lim) {
			from = lim
		}
		window := time.Duration(t.WindowSec) * time.Second
		var due *time.Time
		skipped := 0
		var skipBase time.Time
		for _, b := range t.BasesFor(nodeID, from, now) {
			b := b
			runAt := b.Add(s.runOffset(nodeID, t, b))
			if now.Before(runAt) {
				continue // its time in the window has not come yet; Last stays behind it
			}
			if now.After(b.Add(window + schedGrace)) {
				skipped++
				skipBase = b
				s.st.Last[t.ID] = b.Unix()
				dirty = true
				continue
			}
			due = &b
		}
		if skipped > 0 {
			s.addLocked(SchedRun{Task: t.ID, Name: t.Name, Action: t.Action, Base: skipBase.Unix(), Start: now.Unix(), End: now.Unix(), Status: "skipped",
				Output: fmt.Sprintf("%d scheduled run(s) were missed (this node was down or busy) and were past their window when it came back", skipped)})
		}
		if due == nil {
			continue
		}
		s.st.Last[t.ID] = due.Unix()
		dirty = true
		if s.running[t.ID] || s.queuedLocked(t.ID) {
			s.addLocked(SchedRun{Task: t.ID, Name: t.Name, Action: t.Action, Base: due.Unix(), Start: now.Unix(), End: now.Unix(), Status: "skipped", Output: "the previous run was still going or waiting"})
			continue
		}
		if len(s.running) > 0 { // one job at a time: wait for the one that is running
			s.st.Queue = append(s.st.Queue, schedQueued{ID: t.ID, Base: due.Unix()})
			continue
		}
		s.startLocked(t, due.Unix(), "schedule")
	}
	for id := range s.st.Last { // tasks that were deleted
		if !known[id] {
			delete(s.st.Last, id)
			dirty = true
		}
	}
	s.drainLocked()
	if dirty || len(s.st.Queue) > 0 {
		s.saveLocked()
	}
}

// startLocked begins a run in the background (the caller holds s.mu).
func (s *Scheduler) startLocked(t core.SchedTask, base int64, actor string) {
	s.running[t.ID] = true
	r := SchedRun{Task: t.ID, Name: t.Name, Action: t.Action, Base: base, Start: s.now().Unix(), Status: "running"}
	s.addLocked(r)
	start := r.Start
	s.saveLocked()
	go func() {
		out, err := s.execute(t, actor)
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.running, t.ID)
		status := "ok"
		if err != nil {
			status = "failed"
			out = strings.TrimSpace(out + "\n" + err.Error())
		}
		// the entry may have moved if the history was trimmed meanwhile: find it again
		for i := len(s.st.History) - 1; i >= 0; i-- {
			if h := &s.st.History[i]; h.Task == t.ID && h.Start == start && h.Status == "running" {
				h.End, h.Status, h.Output = s.now().Unix(), status, tail(out, schedOutputMax)
				break
			}
		}
		s.saveLocked()
		s.drainLocked()
		if err != nil {
			core.Warnf("scheduler: task %q failed: %v", t.Name, err)
		} else {
			core.Infof("scheduler: task %q finished", t.Name)
		}
	}()
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// RunNow runs a task on this node at once, whatever its schedule says.
func (s *Scheduler) RunNow(id, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tasks {
		if t.ID != id {
			continue
		}
		if s.running[id] {
			return errors.New("that task is running now")
		}
		if len(s.running) > 0 {
			return errors.New("another task is running; tasks run one at a time")
		}
		core.Warnf("scheduler: %q ran task %q now", actor, t.Name)
		s.startLocked(t, 0, actor)
		return nil
	}
	return errors.New("no such task")
}

// execute does the task's work.
func (s *Scheduler) execute(t core.SchedTask, actor string) (string, error) {
	core.Infof("scheduler: running task %q on this node", t.Name)
	if t.Action != "shell" {
		return s.act(t.Action, "scheduler: "+t.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(t.TimeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", t.Command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) } // the whole group, not only the shell
	cmd.WaitDelay = 5 * time.Second
	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, n: 1 << 20}
	cmd.Stdout, cmd.Stderr = lw, lw // one writer for both: they share one pipe, and the output stays in order
	cmd.Env = schedEnv(os.Environ(), t.Name)
	err := cmd.Run()
	lw.mu.Lock()
	out := buf.String()
	lw.mu.Unlock()
	if ctx.Err() != nil {
		return out, fmt.Errorf("stopped after %d s", t.TimeoutSec)
	}
	var ee *exec.ExitError
	if t.IgnoreExit && errors.As(err, &ee) {
		return strings.TrimRight(out, "\n") + fmt.Sprintf("\n(exit status %d, ignored)", ee.ExitCode()), nil
	}
	return out, err
}

type limitWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
	n  int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}

// builtin runs one of the built-in actions on this node.
func (s *Scheduler) builtin(action, actor string) (string, error) {
	switch action {
	case "node_pause", "node_resume":
		return s.m.NodePause(action == "node_pause", actor)
	case "update_online":
		return s.updateOnline(actor)
	case "backup":
		if s.m.backup == nil {
			return "", errors.New("backups are not available on this node")
		}
		return s.m.backup.RunScheduled(actor)
	case "node_reboot":
		return s.rebootHost(actor)
	}
	return "", fmt.Errorf("unknown action %q", action)
}

// ── what the page and the CLI see ────────────────────────────────────────────

// SchedTaskView is a task as the page shows it for this node.
type SchedTaskView struct {
	Name     string         `json:"name"`
	Action   string         `json:"action"`
	Disabled bool           `json:"disabled"`
	ID       string         `json:"id"`
	Describe string         `json:"describe"`
	Applies  bool           `json:"applies"`
	Running  bool           `json:"running"`
	Queued   bool           `json:"queued,omitempty"`
	Next     int64          `json:"next,omitempty"`     // the next scheduled time (unix)
	NextRun  int64          `json:"next_run,omitempty"` // when this node will run it (the scheduled time plus this node's offset)
	Last     *SchedRun      `json:"last,omitempty"`
	Task     core.SchedTask `json:"task"`
}

// SchedStatus is the answer of schedule.status: this node's view of the task list and its history (newest first).
type SchedStatus struct {
	NodeID  string            `json:"node_id"`
	Now     int64             `json:"now"`
	Tasks   []SchedTaskView   `json:"tasks"`
	History []SchedRun        `json:"history"`
	Actions map[string]string `json:"actions"`
	// AutoUpdate says auto-update is on: the form then lets the online update run on one node only.
	AutoUpdate bool `json:"auto_update,omitempty"`
}

func (s *Scheduler) Status() SchedStatus {
	node := core.LocalNodeID()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := SchedStatus{NodeID: node, Now: now.Unix(), Tasks: []SchedTaskView{}, History: []SchedRun{}, Actions: core.SchedActions, AutoUpdate: s.m != nil && s.m.upd != nil && s.m.upd.Intent().AutoAll}
	for _, t := range s.tasks {
		t := t
		v := SchedTaskView{ID: t.ID, Name: t.Name, Action: t.Action, Disabled: t.Disabled, Task: t, Describe: t.Describe(), Applies: t.AppliesTo(node), Running: s.running[t.ID], Queued: s.queuedLocked(t.ID)}
		if !t.Disabled {
			// the next run of this node: an occurrence whose own time in the window has not yet passed counts too
			from := now.Add(-time.Duration(t.WindowSec) * time.Second)
			for _, b := range t.BasesFor(node, from, now) {
				if runAt := b.Add(s.runOffset(node, t, b)); runAt.After(now) && b.Unix() > s.st.Last[t.ID] {
					v.Next, v.NextRun = b.Unix(), runAt.Unix()
					break
				}
			}
			if v.Next == 0 {
				if b := t.NextFor(node, now); !b.IsZero() {
					v.Next, v.NextRun = b.Unix(), b.Add(s.runOffset(node, t, b)).Unix()
				}
			}
		}
		for i := len(s.st.History) - 1; i >= 0; i-- {
			if s.st.History[i].Task == t.ID {
				r := s.st.History[i]
				v.Last = &r
				break
			}
		}
		out.Tasks = append(out.Tasks, v)
	}
	for i := len(s.st.History) - 1; i >= 0; i-- {
		out.History = append(out.History, s.st.History[i])
	}
	return out
}

// schedEnv is the environment of a shell task: the daemon's own, with the usual system and local command directories
// on the PATH (a service started by systemd may have a short one or none) and HOME set, so a plain `ls` or `systemctl`
// is found as it would be in a root shell.
func schedEnv(base []string, task string) []string {
	const std = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	var out []string
	path, home := "", false
	for _, e := range base {
		switch {
		case strings.HasPrefix(e, "PATH="):
			path = e[5:]
		case strings.HasPrefix(e, "HOME="):
			home = true
			out = append(out, e)
		case strings.HasPrefix(e, "NETDIR_TASK=") || strings.HasPrefix(e, "DNSDIR_TASK="):
		default:
			out = append(out, e)
		}
	}
	have := map[string]bool{}
	for _, p := range strings.Split(path, ":") {
		have[p] = true
	}
	for _, p := range strings.Split(std, ":") {
		if !have[p] {
			if path != "" {
				path += ":"
			}
			path += p
		}
	}
	out = append(out, "PATH="+path)
	if !home {
		out = append(out, "HOME=/root")
	}
	return append(out, "NETDIR_TASK="+task)
}

func strconvI(n int64) string { return strconv.FormatInt(n, 10) }
