package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netdir/device"
	"netdir/internal/cluster"
	"netdir/internal/core"
	"netdir/internal/web"
)

// Mgmt is the management layer the CLI (over the status socket) and the web
// GUI both call: configuration with history, the GUI certificate, the
// cluster, and software updates.  Keeping one implementation behind both
// front ends is what guarantees GUI/CLI parity.
type Mgmt struct {
	confPath string
	stateDir string
	alerts   *AlertEngine       // this node's alerts (alerts.go)
	backup   *core.BackupEngine // this node's backups (backup.go)

	capture core.CaptureState // this node's Capture page
	capjobs capJobs           // the cluster-wide capture
	capruns capRuns           // timed captures started on this node (by the cluster-wide one, from another node)

	versions *cluster.VersionStore
	certs    *core.CertManager
	upd      *core.Updater
	cl       *cluster.Cluster
	sched    *Scheduler // the scheduled tasks of this node (Operate ▸ Scheduler)

	cfgMu sync.Mutex // serialises writes of the config file
	// pendShared: a replica that has had a change to the shared settings accepted by the primary waits for the primary's
	// state at that revision (or newer) before it takes any shared settings from the primary: an older state still on its
	// way would put the old values back for a few seconds (under cfgMu).
	pendShared struct {
		rev   uint64
		until time.Time
	}
	webPolicy atomic.Pointer[core.WebConfig]

	// endSessions signs a user out of the web GUI sessions of this node (set by the web server)
	endSessions atomic.Pointer[func(user string)]

	reloadFn  func() error               // re-read the config file and apply it
	restartFn func()                     // gracefully re-exec this process
	gwFn      func() []core.GwState      // which gateways this node is serving right now
	gwIPsFn   func() []string            // the addresses this node uses in the gateway protocol, one per family of each group
	pausedFn  func() bool                // whether this whole node is paused (Operate ▸ Node)
	anycastFn func() []core.AnycastState // the anycast addresses and whether each is announced now
	tshootFn  func() map[string]any      // what only the status server knows, for the troubleshooting bundle (see tshoot.go)
	othersFn  func() int                 // how many other nodes are in service (tests replace it; nil asks the cluster)
	lastFn    func() string              // names a gateway only this node serves, "" if none (tests replace it; nil asks the cluster)
	servMu    sync.Mutex
	servSince map[int]time.Time // when each gateway started being served continuously
	bgp       *core.BGPManager  // keeps FRR in line with the BGP settings
	webH      http.Handler      // the web API, for requests relayed from other cluster nodes
	cancelFn  context.CancelFunc
}

// What the cluster asks of this node (ClusterHost).
func (m *Mgmt) Updater() *core.Updater          { return m.upd }
func (m *Mgmt) Certs() *core.CertManager        { return m.certs }
func (m *Mgmt) Versions() *cluster.VersionStore { return m.versions }
func (m *Mgmt) StateDir() string                { return m.stateDir }
func (m *Mgmt) ConfPath() string                { return m.confPath }
func (m *Mgmt) KnowsGateways() bool             { return m.gwFn != nil }
func (m *Mgmt) Cluster() *cluster.Cluster       { return m.cl }
func (m *Mgmt) Backup() *core.BackupEngine      { return m.backup }
func (m *Mgmt) WebHandler() http.Handler        { return m.webH }

// AttachWeb is how the web server of this node makes itself known (WebHost).
func (m *Mgmt) AttachWeb(_ *web.WebServer, endSessions func(user string)) {
	m.endSessions.Store(&endSessions)
}

func (m *Mgmt) NodePaused() bool { return m.pausedFn != nil && m.pausedFn() }

// KnowsNodePause says whether NodePaused comes from the running node (false in tests that build a bare Mgmt).
func (m *Mgmt) KnowsNodePause() bool { return m.pausedFn != nil }

// defaultStateDir holds history, certificates, cluster identity and update
// files.  It is root-only.
const defaultStateDir = "/var/lib/netdir"

// NewMgmt builds the management layer for the given initial config.
func NewMgmt(confPath, stateDir string, dc *core.DaemonConfig) (*Mgmt, error) {
	// absolute paths: the update build runs go with its own working directory
	// and the daemon may re-exec itself, so nothing may depend on our cwd.
	if abs, err := filepath.Abs(stateDir); err == nil {
		stateDir = abs
	}
	if abs, err := filepath.Abs(confPath); err == nil {
		confPath = abs
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory %s: %w", stateDir, err)
	}
	m := &Mgmt{confPath: confPath, stateDir: stateDir}
	device.EntraRefreshed = m.entraRefreshed // a renewed Microsoft sign-in is stored in its login (devsignin.go)
	m.sched = newScheduler(m, stateDir)
	m.sched.SetTasks(dc.Settings.Schedule)
	m.bgp = core.NewBGPManager(stateDir)
	w := dc.Web
	m.webPolicy.Store(&w)
	var err error
	if m.versions, err = cluster.NewVersionStore(filepath.Join(stateDir, "versions")); err != nil {
		return nil, err
	}
	m.certs = core.NewCertManager(stateDir, confPath, func() core.WebConfig { return *m.webPolicy.Load() })
	if m.upd, err = core.NewUpdater(stateDir); err != nil {
		return nil, err
	}
	if m.cl, err = cluster.NewCluster(m, dc.Cluster); err != nil {
		return nil, err
	}
	m.cl.SetRoutes(map[string]cluster.PeerHandler{"POST /cluster/proxy": m.peerProxy})
	return m, nil
}

// ── configuration ────────────────────────────────────────────────────────────

// LiveConfig reads the config file (defaults if absent) and its canonical bytes.
func (m *Mgmt) LiveConfig() (*core.DaemonConfig, []byte, error) {
	dc, err := core.LoadConfig(m.confPath)
	if err != nil {
		return nil, nil, err
	}
	b, _ := json.Marshal(dc)
	return dc, b, nil
}

// OnConfigLoaded is called every time a (valid) config has been loaded and
// applied, whoever changed it: it records a version, tracks the shared
// revision, and propagates hot-applicable settings.
func (m *Mgmt) OnConfigLoaded(dc *core.DaemonConfig) {
	w := dc.Web
	m.webPolicy.Store(&w)
	m.bgp.Apply(dc)
	core.SysSink.Apply(dc.Syslog)
	core.DnsRegistrar.Apply(dc)
	m.sched.SetTasks(dc.Settings.Schedule)
	m.certs.Refresh()
	if _, raw, err := m.LiveConfig(); err == nil {
		if _, err := os.Stat(m.confPath); err == nil { // don't version a config that doesn't exist yet
			if meta, err := m.versions.Record(raw, "file edit", "", false); err != nil {
				core.Warnf("config history: %v", err)
			} else if meta != nil {
				core.Infof("config history: recorded version %s (%s) — %s", meta.ID, meta.Actor, meta.Summary)
			}
		}
	}
	m.cl.OnConfig(dc)
	// the devices or their logins may have changed: the drivers kept open for reads are closed (device/pool.go)
	device.CacheFlush() // and what was learned about them (device/cache.go, answercache.go)
	device.Answers.Flush()
	if n := device.PoolFlush(); n > 0 {
		core.Debugf("devices: %d kept connection(s) closed: the configuration was loaded", n)
	}
}

// keepNodePaused makes dc carry this node's live pause flag.  Whether the whole node is paused is changed only by
// NodePause (Operate ▸ Node, the node menu, --node-pause): a configuration that comes from outside (a page that fetched it
// earlier, an import, an old version) must not flip it, or pausing a server could pause the node, as an old copy said.
func (m *Mgmt) KeepNodePaused(dc *core.DaemonConfig) {
	if cur, _, err := m.LiveConfig(); err == nil {
		dc.NodePaused = cur.NodePaused
	}
}

// PutConfig validates dc and makes it the node's configuration.  On a replica,
// a change to the shared settings is first accepted by the primary.
func (m *Mgmt) PutConfig(dc *core.DaemonConfig, actor, note string) error {
	return m.PutConfigBase(dc, actor, note, "")
}

// PutConfigBase is PutConfig for a page that read the configuration earlier: base is the token it got with it (configBase).  When the
// shared settings are not the ones it read, nothing is saved (ErrConfigChanged): a page that is hours old must not write its old
// copy over the devices somebody imported since.  An empty base (the CLI, the API, an import file) saves as before.
func (m *Mgmt) PutConfigBase(dc *core.DaemonConfig, actor, note, base string) error {
	if err := dc.Validate(); err != nil {
		return err
	}
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	cur, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if base != "" && base != core.ConfigBase(cur) {
		return core.ErrConfigChanged
	}
	if err := checkVIPsNotNodes(cur, dc, m.cl); err != nil {
		return err
	}
	if m.cl.Enabled() {
		if err := gatewayNamesNeedNewNodes(cur, dc, m.cl.View().Peers); err != nil {
			return err
		}
	}
	if m.cl.Enabled() && m.cl.Snapshot().Role == cluster.RoleReplica && core.SharedOf(dc).Hash() != core.SharedOf(cur).Hash() {
		payload := adminSharedConfig{Shared: core.SharedOf(dc), Seeds: cluster.SeedsOf(dc), Base: base}
		out, err := m.cl.ForwardAdmin("shared-config", actor, payload)
		if err != nil {
			if strings.Contains(err.Error(), core.ErrConfigChanged.Error()) {
				return core.ErrConfigChanged // the primary has settings the page never read
			}
			return fmt.Errorf("this node is a replica: the change to the shared settings must be accepted by the primary (%s), and that failed: %w",
				m.cl.Snapshot().PrimaryAddr, err)
		}
		var ans struct {
			Rev uint64 `json:"rev"`
		}
		if json.Unmarshal(out, &ans) == nil && ans.Rev > 0 {
			m.pendShared.rev, m.pendShared.until = ans.Rev, time.Now().Add(pendSharedWait)
		}
	}
	m.versions.Expect(actor, note)
	if err := dc.Save(m.confPath); err != nil {
		return fmt.Errorf("could not save: %w", err)
	}
	if m.reloadFn != nil {
		if err := m.reloadFn(); err != nil {
			return fmt.Errorf("saved, but applying failed: %w", err)
		}
	}
	return nil
}

// pendSharedWait is the longest a replica waits for the primary to report the revision its own change made.
const pendSharedWait = time.Minute

// applyClusterShared writes the primary's shared settings into the local file.
func (m *Mgmt) ApplyClusterShared(sh core.SharedConfig, seeds []cluster.GroupSeed, rev uint64, from string) {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	cur, _, err := m.LiveConfig()
	if err != nil {
		core.Warnf("cluster: cannot read local config: %v", err)
		return
	}
	if m.pendShared.rev != 0 {
		if time.Now().After(m.pendShared.until) || rev >= m.pendShared.rev {
			m.pendShared.rev = 0
		} else {
			core.Debugf("cluster: not applying shared settings rev %d from %s: a newer one (rev %d) is on its way", rev, from, m.pendShared.rev)
			return
		}
	}
	hash := sh.Hash()
	changed, err := cluster.MergeShared(cur, sh, seeds)
	if err != nil {
		core.Warnf("cluster: shared settings from the primary were refused by local validation: %v", err)
		return
	}
	if !changed {
		m.cl.Node.SetShared(rev, hash)
		return
	}
	m.versions.Expect("cluster sync", fmt.Sprintf("shared settings rev %d from %s", rev, from))
	if err := cur.Save(m.confPath); err != nil {
		core.Warnf("cluster: cannot save the synced config: %v", err)
		return
	}
	m.cl.Node.SetShared(rev, hash)
	core.Infof("cluster: applied shared settings rev %d from %s", rev, from)
	if m.reloadFn != nil {
		if err := m.reloadFn(); err != nil {
			core.Warnf("cluster: applying synced config failed: %v", err)
		}
	}
}

// ConfigImport replaces the whole configuration with an uploaded document.
func (m *Mgmt) ConfigImport(raw []byte, actor, note string) (*core.DaemonConfig, error) {
	dc := core.NewDaemonConfig()
	if err := json.Unmarshal(raw, dc); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	m.KeepNodePaused(dc)
	if err := m.PutConfig(dc, actor, note); err != nil {
		return nil, err
	}
	return dc, nil
}

// ── versions ─────────────────────────────────────────────────────────────────

func (m *Mgmt) VersionsList() []cluster.VersionMeta { return m.versions.List() }

func (m *Mgmt) VersionGet(id string) (cluster.VersionMeta, json.RawMessage, error) {
	if id == cluster.CurrentVersionID {
		_, raw, err := m.LiveConfig()
		if err != nil {
			return cluster.VersionMeta{}, nil, err
		}
		_, canon, err := cluster.CanonicalConfig(raw)
		return cluster.VersionMeta{ID: cluster.CurrentVersionID, Summary: "live configuration", At: time.Now().UTC()}, canon, err
	}
	meta, cfg, err := m.versions.Get(id)
	return meta, cfg, err
}

func (m *Mgmt) VersionDiff(a, b string) (*cluster.VersionDiff, error) {
	_, raw, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	if b == "" {
		b = cluster.CurrentVersionID
	}
	return m.versions.Diff(a, b, raw)
}

func (m *Mgmt) VersionSnapshot(note, by string) (*cluster.VersionMeta, error) {
	_, raw, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	return m.versions.Record(raw, by, strings.TrimSpace(note), true)
}

// VersionRestore makes a recorded version the live configuration (itself
// recorded as a new version).  On a replica the shared part must be accepted
// by the primary, like any other edit.
func (m *Mgmt) VersionRestore(id, by string) (*core.DaemonConfig, error) {
	meta, cfg, err := m.versions.Get(id)
	if err != nil {
		return nil, err
	}
	dc := core.NewDaemonConfig()
	if err := json.Unmarshal(cfg, dc); err != nil {
		return nil, err
	}
	// keep a way back to what is live right now
	if _, raw, err := m.LiveConfig(); err == nil {
		if _, err := os.Stat(m.confPath); err == nil {
			m.versions.Record(raw, by, "before restoring version "+id, false)
		}
	}
	m.KeepNodePaused(dc)
	if err := m.PutConfig(dc, by, "restored version "+meta.ID); err != nil {
		return nil, err
	}
	return dc, nil
}

// ── certificate ──────────────────────────────────────────────────────────────

// shareCert reports whether certificate changes go through the primary.
func (m *Mgmt) shareCert() bool {
	if !m.cl.Enabled() {
		return false
	}
	dc, _, err := m.LiveConfig()
	return err == nil && dc.Cluster.ShareCert
}

func (m *Mgmt) TLSInstall(certPEM, keyPEM, by string) (core.CertInfo, []string, error) {
	if m.shareCert() && m.cl.Snapshot().Role == cluster.RoleReplica {
		// the primary validates and installs it; it comes back via sync
		raw, err := m.cl.ForwardAdmin("cert-install", by, core.AdminCert{CertPEM: certPEM, KeyPEM: keyPEM})
		if err != nil {
			return core.CertInfo{}, nil, fmt.Errorf("this node is a replica: the primary must install the certificate, and that failed: %w", err)
		}
		var res struct {
			Warnings []string `json:"warnings"`
		}
		json.Unmarshal(raw, &res)
		m.cl.SyncNow()
		return m.certs.Status(), res.Warnings, nil
	}
	return m.certs.Install([]byte(certPEM), []byte(keyPEM), by, core.CertSourceInstalled)
}

func (m *Mgmt) TLSRevert(by string) (core.CertInfo, error) {
	if m.shareCert() && m.cl.Snapshot().Role == cluster.RoleReplica {
		if _, err := m.cl.ForwardAdmin("cert-revert", by, nil); err != nil {
			return core.CertInfo{}, err
		}
		m.cl.SyncNow()
		return m.certs.Status(), nil
	}
	return m.certs.Revert(by)
}

// ── updates ──────────────────────────────────────────────────────────────────

// UpdateUpload stages a release archive on this node.
func (m *Mgmt) UpdateUpload(body []byte, by string) (string, error) {
	if len(body) == 0 {
		return "", errors.New("empty upload")
	}
	if len(body) > core.MaxUploadBytes {
		return "", errors.New("upload too large")
	}
	ver, err := m.upd.ExtractSource(body)
	if err != nil {
		return "", fmt.Errorf("rejected: %w", err)
	}
	m.upd.ReleaseSource() // staged on purpose: it may be offered to the cluster
	m.upd.Record(core.UpdateEvent{Node: m.cl.SelfAddrForEvents(), Kind: "uploaded", To: ver, By: by,
		Detail: fmt.Sprintf("source v%s staged (running v%s)", ver, core.Version())})
	core.Infof("update: source v%s staged by %s", ver, by)
	return ver, nil
}

// UpdateApplyLocal starts building the staged source and restarts into it.
// The build can take minutes, so it runs in the background: progress shows in
// UpdateStatus (busy/phase, history).  Preconditions are checked up front.
func (m *Mgmt) UpdateApplyLocal(by string, force bool) (string, error) {
	target := m.upd.SourceVersion()
	switch {
	case target == "":
		return "", errors.New("no source tree staged: upload a release archive first")
	case !core.VersionGreater(target, core.Version()):
		return "", fmt.Errorf("the staged source (v%s) is not newer than the running version (v%s)", target, core.Version())
	case m.upd.Busy():
		return "", errors.New("an update is already in progress on this node")
	}
	if ok, why := m.updateSafeToApply(); !ok && !force {
		return "", fmt.Errorf("not safe to update this node now: %s (to update anyway: netdir --update-apply --yes, or confirm in the GUI)", why)
	}
	go func() {
		if _, err := m.upd.Apply(context.Background(), m.cl.SelfAddrForEvents(), by); err != nil {
			core.Debugf("update: %v", err)
			return
		}
		m.scheduleRestart(force)
	}()
	return target, nil
}

// restartRecheck is how often a node that has installed an update re-asks
// whether it may go down.
var restartRecheck = 2 * time.Second

// scheduleRestart restarts into the installed version — but only once it is safe
// to go down.  The check made before the update began is not enough: the build
// takes minutes, and meanwhile another member may have gone down for its own
// update, or the one that was serving the gateway alongside this node may have
// failed.  force skips the wait (the operator confirmed it).
func (m *Mgmt) scheduleRestart(force bool) {
	if m.restartFn == nil {
		core.Warnf("update: installed, but this process cannot restart itself — restart netdir to run the new version")
		return
	}
	go func() {
		time.Sleep(1500 * time.Millisecond) // let the HTTP/socket reply go out
		waitUntilSafe(m.updateSafeToApply, force, restartRecheck, m.upd.SetWaiting)
		m.handOverForUpdate("update", "restarting into the update")
		m.restartFn()
	}()
}

// waitUntilSafe blocks until safe reports true (or force), publishing the reason
// it is holding back through setWaiting and clearing it afterwards.
func waitUntilSafe(safe func() (bool, string), force bool, every time.Duration, setWaiting func(string)) {
	if force {
		return
	}
	defer setWaiting("")
	for {
		ok, why := safe()
		if ok {
			return
		}
		setWaiting("installed; waiting to restart: " + why)
		time.Sleep(every)
	}
}

type adminNodes struct {
	Nodes    []string `json:"nodes"`
	Enabled  bool     `json:"enabled"`
	Repo     string   `json:"repo,omitempty"`
	Failover string   `json:"failover,omitempty"`
}

func (m *Mgmt) UpdatePush(nodes []string, by string) error {
	if len(nodes) == 0 {
		return errors.New("no nodes given")
	}
	_, err := m.runOnPrimary("update-push", by, adminNodes{Nodes: nodes})
	return err
}

func (m *Mgmt) UpdateCancel(nodes []string, by string) error {
	_, err := m.runOnPrimary("update-cancel", by, adminNodes{Nodes: nodes})
	return err
}

// UpdateRepo sets the repository "Fetch from online" downloads from (a GitHub URL or owner/repo; empty or "default" for the
// default one); shared by the cluster.
func (m *Mgmt) UpdateRepo(repo, by string) error {
	norm, err := web.NormalizeRepo(repo)
	if err != nil {
		return err
	}
	_, err = m.runOnPrimary("update-repo", by, adminNodes{Repo: norm})
	return err
}

func (m *Mgmt) UpdateAuto(on bool, by string) error {
	_, err := m.runOnPrimary("update-auto", by, adminNodes{Enabled: on})
	return err
}

// runOnPrimary executes an admin write on the primary: here if this node is
// the primary (or not clustered), otherwise forwarded.
func (m *Mgmt) runOnPrimary(op, by string, payload any) (json.RawMessage, error) {
	if !m.cl.Enabled() || m.cl.Snapshot().Role == core.RolePrimary {
		b, _ := json.Marshal(payload)
		return m.ExecAdminOp(op, by, b)
	}
	return m.cl.ForwardAdmin(op, by, payload)
}

type adminSharedConfig struct {
	Shared core.SharedConfig   `json:"shared"`
	Seeds  []cluster.GroupSeed `json:"seeds"`
	Base   string              `json:"base,omitempty"` // what the page read (configBase): the primary refuses when its own settings are not those
}

// execAdminOp runs a write on this node, which must be the primary.
func (m *Mgmt) ExecAdminOp(op, by string, payload json.RawMessage) (json.RawMessage, error) {
	ok := func(v any) (json.RawMessage, error) { b, _ := json.Marshal(v); return b, nil }
	switch op {
	case "shared-config":
		var p adminSharedConfig
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if err := p.Shared.Validate(); err != nil {
			return nil, err
		}
		m.cfgMu.Lock()
		defer m.cfgMu.Unlock()
		cur, _, err := m.LiveConfig()
		if err != nil {
			return nil, err
		}
		// The replica checked the page's base against its own copy, which can be behind the primary's (an import made on the primary a
		// moment ago): only the primary knows what is really saved, so it checks too, or the replica's old copy overwrites it.
		if p.Base != "" && p.Base != core.ConfigBase(cur) {
			return nil, core.ErrConfigChanged
		}
		if _, err := cluster.MergeShared(cur, p.Shared, p.Seeds); err != nil {
			return nil, err
		}
		m.versions.Expect(by, "shared settings changed on a replica")
		if err := cur.Save(m.confPath); err != nil {
			return nil, err
		}
		if m.reloadFn != nil {
			if err := m.reloadFn(); err != nil {
				return nil, err
			}
		}
		return ok(map[string]any{"rev": m.cl.Snapshot().SharedRev})
	case "cert-install":
		var p core.AdminCert
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		info, warns, err := m.certs.Install([]byte(p.CertPEM), []byte(p.KeyPEM), by, core.CertSourceInstalled)
		if err != nil {
			return nil, err
		}
		return ok(map[string]any{"info": info, "warnings": warns})
	case "cert-revert":
		if _, err := m.certs.Revert(by); err != nil {
			return nil, err
		}
		return ok(map[string]any{})
	case "update-push", "update-cancel", "update-auto", "update-done", "update-repo":
		var p adminNodes
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		switch op {
		case "update-push":
			m.upd.Push(p.Nodes, by)
		case "update-cancel", "update-done":
			m.upd.Cancel(p.Nodes, by)
		case "update-auto":
			m.upd.SetAuto(p.Enabled, by, m.cl.SelfAddrForEvents())
		case "update-repo":
			norm, err := web.NormalizeRepo(p.Repo)
			if err != nil {
				return nil, err
			}
			m.upd.SetRepo(norm, by, m.cl.SelfAddrForEvents())
		}
		return ok(map[string]any{})
	}
	return nil, fmt.Errorf("unknown admin operation %q", op)
}

// UpdateView is the update status for the CLI/GUI.
type UpdateView struct {
	Running       string             `json:"running"`
	SourceVersion string             `json:"source_version"`
	Intent        core.UpdateIntent  `json:"intent"`
	Nodes         []core.UpdateNode  `json:"nodes"`
	History       []core.UpdateEvent `json:"history"`
	Toolchain     string             `json:"toolchain"`
	Notice        string             `json:"notice,omitempty"`
	Busy          bool               `json:"busy"`
	Phase         string             `json:"phase,omitempty"`
	Self          string             `json:"self"`
	Clustered     bool               `json:"clustered"`
	Last          *core.UpdateEvent  `json:"last,omitempty"`
	Extra         map[string]any     `json:"extra,omitempty"`
	Waiting       string             `json:"waiting,omitempty"` // why this node is holding back its queued update
}

func (m *Mgmt) UpdateStatus() UpdateView {
	// History(0) is every event kept: the GUI pages through them.
	v := UpdateView{
		Running: core.Version(), SourceVersion: m.upd.SourceVersion(), Intent: m.upd.Intent(),
		History: m.upd.History(0), Busy: m.upd.Busy(), Phase: m.upd.Phase(), Notice: m.upd.RolledBackNotice(),
		Self: m.cl.SelfAddrForEvents(), Clustered: m.cl.Enabled(), Last: m.upd.LastEvent(), Waiting: m.upd.Waiting(),
	}
	if g, err := m.upd.FindGo(); err == nil {
		v.Toolchain = g
	}
	nodes := m.cl.UpdateNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Addr < nodes[j].Addr })
	v.Nodes = nodes
	return v
}

// localGwIPs is this node's addresses in the gateway protocol (nil before the supervisor exists).
func (m *Mgmt) LocalGwIPs() []string {
	if m.gwIPsFn == nil {
		return nil
	}
	return m.gwIPsFn()
}

// closeDevicePool closes the device drivers kept open for reads (the daemon is stopping).
func closeDevicePool() { device.PoolFlush() }

// gatewayNamesFromVersion is the first version that keeps a gateway's fqdn and anycast_fqdn when it shares the settings.
const gatewayNamesFromVersion = 236

// gatewayNamesNeedNewNodes refuses a change to a gateway's VIP FQDN or Anycast FQDN while a node of the cluster runs a version that does
// not know them: that node would drop the names when the primary's settings reach it (or, as the primary, when it shares them), and they
// would disappear from every node a moment after they were saved.  Said now, with the node's name, instead of lost silently.
func gatewayNamesNeedNewNodes(cur, dc *core.DaemonConfig, peers []core.PeerView) error {
	had := map[int][2]string{}
	if cur != nil {
		for _, g := range cur.Groups {
			had[g.GroupID] = [2]string{g.FQDN, g.AnycastFQDN}
		}
	}
	changed := false
	for _, g := range dc.Groups {
		if (g.FQDN != "" || g.AnycastFQDN != "") && had[g.GroupID] != [2]string{g.FQDN, g.AnycastFQDN} {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	for _, p := range peers {
		if p.Self || p.Version == "" {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(p.Version), "v")); err == nil && n < gatewayNamesFromVersion {
			name := core.FirstNonEmpty(p.Hostname, p.Addr)
			return fmt.Errorf("node %s runs version %d, which drops the VIP FQDN and Anycast FQDN when it shares the settings: update it to version %d or later (Operate ▸ Upgrade), then set the names", name, n, gatewayNamesFromVersion)
		}
	}
	return nil
}
