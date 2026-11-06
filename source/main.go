// netdir — MCP Network Director: a highly available MCP gateway to the network's switches and firewalls.  A cluster of
// nodes shares a VIP (the Distributed Gateway Load Balancing Protocol) and anycast addresses, and every node answers
// MCP on them and reaches the managed devices for its callers.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const usageText = `netdir — MCP Network Director (an MCP gateway to switches and firewalls, on a shared VIP)
Run as a systemd service or directly. All options are runtime-configurable
and persisted to /var/lib/netdir/netdir.conf.

Usage:
    netdir [options]
    netdir ?|-h|--help
    netdir --configure       interactive configuration wizard
    netdir --show-config     print current configuration

Options:
  --log-level LEVEL     debug|info|warning|error (default: info)
  --configure           Interactive configuration wizard (edits all groups)
  --show-config         Print current configuration and exit
  --show-neighbors      Print live neighbor table and exit
  --show-gateways       Print all nodes per group with role (AGC/AFN) and exit
  --canvas              Print the gateway diagram as a tree with live status
  --version             Print the release number and exit
  --assert-agc          Make this node the active gateway (AGC) for all groups
  --config FILE         Config file path (default: /var/lib/netdir/netdir.conf)
  --status-socket PATH  Status socket path (default: /run/netdir/netdir.sock)
  --state-dir DIR       Where history, cluster identity, certificates and update
                        data live (default: /var/lib/netdir)

Environment of the daemon:
  NETDIR_MEMORY_LIMIT_PERCENT  memory use (1-99, default 85) at which the memory guard drops the
                        oldest host history

Management commands (talk to the running daemon; root only; every one is also in
the web GUI):
  Topology         --canvas-add gateway --vip ADDR/PREFIX [--vip6 ADDR/PREFIX] [--group N]
                                        [--interface IF] [--label NAME] [--anycast ADDR[,ADDR]]
                   --canvas-add anycast --group N --address ADDR   (one anycast address; see --anycast)
                   --canvas-add device --group N --device NAME   (a device of settings.devices, drawn under the gateway;
                                         --canvas-del device takes it off, --canvas-move device --to N reorders)
                   --device-change "ENGLISH" --target DEVICES [--dry-run] [--yes]
                                        (change ports on Catalyst IOS-XE, Arista EOS, Aruba CX and Meraki switches in plain English,
                                         e.g. --device-change 'change the description for ports gi1/0/1-24 to read "devices"'
                                         --target sw1; DEVICES is a name, tag:T, platform:P, gateway:N or all. The plan
                                         is shown first; --dry-run stops there, --yes skips the question.)
                   --device-raw "METHOD PATH" [--device-body TEXT|@FILE] --target DEVICES [--device-save] [--dry-run] [--yes]
                   --device-lines FILE --target DEVICES [--device-save] [--dry-run] [--yes]
                                        (any configuration change in the platform's own terms: a REST request, a PAN-OS
                                         action with an XPath, or lines of CLI configuration for Arista EOS and NX-OS;
                                         planned first, --device-save keeps it over a reboot)
                   tshoot USER [HOURS]   or   --troubleshoot-user USER [--troubleshoot-hours N]
                                        (look a user up in Entra and follow their most recently used device on the Meraki
                                         network over the last N hours (default 6): client, usage, wireless or switch-port health)
                   --device-signin DEVICE
                                        (sign in to Microsoft Entra with a browser: prints a code and a link, then waits)
                   --device-capture IFACE|default --target DEVICES [--capture-filter EXPR] [--capture-seconds N]
                                        (capture packets for a few seconds on a DNS Director, NTP Director, Arista EOS or
                                         F5 BIG-IP and show a summary: the first packets, protocols, busiest address pairs)
                   --canvas-set gateway --group N [--vip A/P] [--vip6 A/P] [--interface IF]
                                        [--label NAME|-]   (a name shown under the address; - clears)
                                        [--anycast ADDR[,ADDR]|-]   (extra addresses of ANY subnet, held on lo
                                         by every running node while it is serving, for BGP or OSPF; - clears)
                                        [--real-macs on|off]   (run without virtual MACs on every node)
                   --tshoot [--all-nodes] [--tshoot-file F.tgz]
                                         (a troubleshooting bundle for support: logs, configuration, gateway, BGP and
                                         anycast state, addresses, routes, neighbors, firewall, FRR, service status, host
                                         numbers, 8 s of ARP / neighbor-discovery traffic per gateway interface, a goroutine dump — of
                                         this node, or of every node with --all-nodes. Passwords, the gateway key, tokens
                                         and join codes are removed. kill -USR1 on a daemon that is up but not answering
                                         writes the goroutine dump to the journal.)
                   --test-vmac [--group N]   (can clients' replies reach this node through virtual MACs? sends an ARP/NS
                                         probe from a throwaway virtual MAC and listens for the answer; changes nothing.
                                         When it says "not delivered": --canvas-set gateway --group N --real-macs on)
                   --canvas-pause|--canvas-resume gateway --group N   (this node stops/starts serving it)
                   --canvas-del node --group N --node NODE   (remove a cluster node from the gateway: it stops serving it, on every
                                         node's view; NODE is its address or host name, as --cluster-status lists them)
                   --canvas-add node --group N --node NODE   (put it back; a node that joins starts out removed from every gateway)
                   --host-lookup IP|NAME   (the reverse name of an address, or the address of a name)
                   --schedule | --schedule-history   (the scheduled tasks and when this node runs them next; what ran, with its output)
                   --schedule-set JSON | --schedule-del ID | --schedule-run ID   (add or replace a task, remove one, run one on this node now)
                   --node-pause | --node-resume | --node-status   (this whole node stops/starts serving)
                   --node-rename NAME   (this node's host name and its /etc/hosts entry; on another node: pick it in the Node menu)
                   --canvas-move anycast --group N --address ADDR --to N   (its place in the list, 1 = top)
                   --canvas-pause|--canvas-resume anycast --group N --address ADDR --scope node|all
                   --canvas-pause|--canvas-resume device --device NAME   (disable / enable a device: a disabled one is never contacted)
                                        (stop/start announcing one anycast address on this node only, or on every node)
                   --canvas-del gateway --group N
                   --canvas-del anycast --group N --address ADDR
  Config history   --versions  --version-show ID  --version-diff A[..B]
                   --version-snapshot [--note TEXT]  --version-restore ID
                   --version-export [ID]  --config-import FILE
  GUI certificate  --tls-status  --tls-install --cert-file F --key-file F
                   --tls-csr --cn NAME [--san NAME_OR_IP,...]
                   --tls-revert  --tls-regenerate
  BGP (FRR)        --bgp   (this node's settings, announced addresses, neighbor and BFD state)
                   --asn N|off [--router-id A.B.C.D|-]     (BGP runs while an AS is set)
                   [--keepalive S] [--hold S] [--as-prepend on|off]   (on: the local AS three more times on every announcement)
                   --bgp-neighbor-add ADDR --remote-as N [--description T] [--password P] [--multihop N]
                   --bgp-neighbor-del ADDR
                   --bgp-disable | --bgp-enable   (stop / restart BGP on this node, settings kept)
                   --bgp-neighbor-disable ADDR | --bgp-neighbor-enable ADDR
                                                 (per node; netdir then owns /etc/frr/frr.conf; BFD is always on)
  OSPF (FRR)       --ospf   (this node's settings, announced addresses, neighbor state; OSPFv2 and OSPFv3)
                   --ospf-router-id A.B.C.D  [--ospf-hello S] [--ospf-dead S] [--ospf-metric N]   (- = default)
                   --ospf-interface-add NAME [--ospf-area A] [--ospf-network point-to-point|broadcast] [--ospf-key K]
                   --ospf-interface-del NAME
                   --ospf-disable | --ospf-enable   (stop / restart OSPF on this node, settings kept)
                   --ospf-interface-disable NAME | --ospf-interface-enable NAME
                                                 (per node; ospfd and ospf6d run only while an interface is set; BFD is always on)
  Syslog           --syslog   (forwarding of this node's log to a syslog server: settings and state)
                   --syslog-server HOST[:PORT]  [--syslog-protocol udp|tcp|tls]  [--syslog-facility daemon|local0..local7]
                   [--syslog-format rfc5424|rfc3164]  [--syslog-ca FILE]  [--syslog-tls-insecure]   (- = default / none)
                   --syslog-disable | --syslog-enable   (settings kept)   --syslog-test   (send a test message)
  LLDP             --lldp   (neighbor discovery: the setting, lldpd on this node, and the switch port of each interface)
                   --lldp-enable | --lldp-disable   (every node of the cluster runs lldpd, or none does; off by default)
  Cluster          --cluster-status  --cluster-token  --cluster-join CODE
                   --cluster-promote  --cluster-remove ADDR
                   --cluster-delete ADDR  --cluster-unremove ADDR  --cluster-leave  --cluster-sync
                   (GUI: the Node menu, top right, configures any member)
  Upgrade          --update-status  --update-history  --update-upload FILE
  Backup           --backup-status  --backup-now  --restore FILE [--restore-password-file F]
                   --update-apply  --update-push all|ADDR,...
                   --update-cancel all|ADDR,...  --update-auto on|off
                   --update-repo URL|default   (where "fetch online" downloads from;
                   default https://github.com/micush/netdir)
  Network tools    --scan ADDR   (nmap of an address, run from this node; needs the nmap package)
                   --ping ADDR|NAME  --traceroute ADDR|NAME   (ping / mtr, run from this node; needs ping and mtr)
                   --whois NAME   (registration data of a host name or address, asked of its registry from this node)
  Capture          --capture IFACE [--capture-seconds N] [--capture-filter EXPR] [--capture-file FILE] [--all-nodes]
                   --capture - --group N --capture-file FILE.tgz   (one gateway: its nodes only, its interface and its addresses)
                   --capture-interfaces   (a packet capture on this node, printed or written as .pcap;
                                           --all-nodes: every cluster node at once, one .pcap each in a .tgz)
  Host             --host [--host-range 1h|1d|7d|30d] [--all-nodes]   (CPU, memory, disk and network use; the cluster as one)
  Log              --log [--log-min debug|info|warn|error] [--log-grep WORDS]
                   [--log-since 15m|6h|2d] [--log-lines N]   (the whole log if no --log-lines)
  Users            --users   (the accounts that may sign in to the web GUI)
                   --user-add NAME [--expires YYYY-MM-DD]   (asks for the password)
                   --user-passwd NAME   --user-del NAME
                   --user-grant NAME   (an account that already exists joins the group)   --user-revoke NAME
                   --user-expiry NAME --expires YYYY-MM-DD|never
  Power            --power restart|shutdown [--in MINUTES | --at HH:MM]
                   --power cancel  --power status
                   (restarts or shuts down the whole host; refused while it is the only
                   node serving a gateway unless --yes)
  Modifiers        --yes (no confirmation)  --no-wait (do not wait for a restart)

Per-group settings are managed via --configure or by editing the config
file directly. Each group entry supports:
  group_id, interface, vip4, vip6, priority, lb_method, weight,
  hello_ms, hold_ms, preempt, max_afns, key, neighbors, real_macs, extra_vips

  vip4: IPv4 VIP with prefix, e.g. 10.0.0.1/24  (required when no vip6)
  vip6: IPv6 VIP with prefix, e.g. 2001:db8::1/64 (required when no vip4)
  neighbors: list of peer IP addresses for unicast mode (optional).
    When present, netdir sends hellos directly to each neighbor via unicast
    instead of multicast — required when peers are on different VNIs or
    separated by a routed boundary.
  Every ACTIVE/FORWARD node answers on the VIP with a listener of its own for the MCP endpoint (/mcp) only, port
  443 unless settings.mcp_port says otherwise; the GUI is not served on a gateway address. A node whose MCP
  listener is not serving withdraws its anycast addresses. An explicit "groups": [] means no gateways.

Shared settings ("settings" block, the same on every node of a cluster):
  mcp_port           the port of the MCP listeners on the gateway addresses (default 443)
  mcp_acl            who may use /mcp by address: "10.1.0.0/24" reads, "10.1.1.50 rw" may also change things
  mcp_keys           keys that may use /mcp from any address ("Authorization: Bearer KEY"); kept with its hash, never shown to MCP
  devices            the managed switches and firewalls: {"name", "platform" (iosxe|nxos|eos|aoscx|fortios|panos|panorama|nios|technitium|bigip|dnsdir|ntpdir|meraki|entra|afc|proxmox|observium|ipfabric|aviatrix), "address", "port",
                     "credential", "tags", "insecure", "ca_pem", "options", "disabled"}
  device_credentials the logins they use: {"name", "username", "password"} or {"name", "token"}; never shown to a
                     read-only account or to any MCP caller
  metrics_acl, snmp_communities, snmp_contact, snmp_acl, lldp, alerts, backup, schedule
  The MCP tools list_devices, device_facts, device_interfaces, device_neighbors, device_ports, device_routes, device_routing, device_firewall,
  device_resources, device_vlans, device_api_get and device_show ask every device a target picks (a name, tag:TAG, platform:PLATFORM or all) at once.

Web GUI ("web" block): everything above is also available in a browser.
  Served over HTTPS (default port 22161). Log in with a system account that
  is a member of the netdir group; passwords are checked through PAM (service
  "netdir", see contrib/pam.d/). The page follows the system light/dark theme.
  The GUI is always on.      listen   default ":22161"
  group                default "netdir"      pam_service  default "netdir"
  session_idle_minutes default 30
  max_failed_logins    default 3   wrong passwords ...
  failed_login_window_minutes default 1    ... within this window lock the
  lockout_minutes      default 15  address (and address with user name) out for this long
  min_password_length  default 8   fewest characters of a password set on the Users page
  The certificate is managed with --tls-* / Configure ▸ Web GUI (the old
  cert_file/key_file settings still work and take precedence).
  Pages: Topology (--canvas, --canvas-add/-del: draw gateways as circles with
  their nodes), Gateways (--show-gateways, --show-neighbors),
  Cluster monitor (--cluster-status), Configure (--show-config,
  --configure: form), History (--versions...), Certificate
  (--tls-...), Node (--assert-agc, --node-pause..., --power), Cluster (--cluster-...), Upgrade (--update-...); the ? at the top right
  opens help for the page. Version is in the header. A certificate installed through the GUI/CLI is
  picked up without restarting the GUI.

Config history: every change (GUI, CLI, cluster sync or a hand edit of the
  file) is stored as a version in <state-dir>/versions (newest 200 kept). Any
  version can be compared, downloaded or restored; secrets are hidden in summaries.

Cluster ("cluster" block; management only, independent of the AGC/AFN election):
  listen             default ":22162" (TCP)
  self               address other nodes use to reach this one, e.g. "10.0.0.5:22162"
  sync_interval_sec  default 5
  One node is the primary, the others replicas. Settings shared by the cluster
  (the settings block, group VIPs/keys/timers, ...) are edited anywhere and applied
  on the primary; interface, priority, weight and the web/cluster blocks stay
  per node. Create a join code on a member (--cluster-token), use it on the new
  node (--cluster-join). Nodes pin each other's certificates and sign requests;
  a code works once for an hour. Promotion is explicit (--cluster-promote), apart from the
  automatic failover (from three members, after 5 minutes) and the hand-over before a planned restart.
  The primary's GUI certificate is replicated to every member.

Updates: upload netdir_vN.tgz (or .zip) on any node (--update-upload); the node
  checks it, keeps the source, and each member that is asked to update (or all of
  them with --update-auto on) pulls it from a peer, builds it with its own Go
  toolchain (gcc + PAM headers needed), swaps the binary and restarts - one node
  at a time. A new binary that fails to start is rolled back automatically.

Live reload: the daemon watches the config file via inotify.
  Edit and save netdir.conf — changes apply within ~50ms, no restart needed.
  Live fields (no engine restart): priority, lb_method, weight,
    hello_ms, hold_ms, preempt, max_afns, log_level, the whole "settings" block,
    web group/pam_service/session timeout, web cert/key (only listen restarts the GUI)
  Restart fields (engine restarts, brief per-group disruption):
    interface, vip4, vip6, group_id, key, neighbors, real_macs
  Adding/removing groups: new groups start, removed groups stop cleanly.`

// the cgroup CPU limit applied at start-up (see cpulimit.go)
var (
	cpuQuota float64
	cpuProcs int
	memLimit int64 // the soft memory limit set for the collector (see memlimit.go)
)

func main() {
	cpuQuota, cpuProcs = limitProcsToCgroup() // logged by the daemon only, not by every CLI command
	memLimit = limitMemoryToCgroup()
	if len(os.Args) > 1 && os.Args[1] == "?" {
		fmt.Println(usageText)
		return
	}
	fs := flag.NewFlagSet("netdir", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		configure    = fs.Bool("configure", false, "")
		showConfig   = fs.Bool("show-config", false, "")
		showNeigh    = fs.Bool("show-neighbors", false, "")
		showGateways = fs.Bool("show-gateways", false, "")
		showVersion  = fs.Bool("version", false, "")
		assertAGC    = fs.Bool("assert-agc", false, "")
		conf         = fs.String("config", confPath, "")
		sock         = fs.String("status-socket", statusSocket, "")
		level        = fs.String("log-level", "", "")
		stateDir     = fs.String("state-dir", defaultStateDir, "")
		restoreFile  = fs.String("restore", "", "")
		restorePwF   = fs.String("restore-password-file", "", "")
		backupNow    = fs.Bool("backup-now", false, "")
		backupStat   = fs.Bool("backup-status", false, "")
		cli          = registerCLIFlags(fs)
	)
	if err := fs.Parse(shortCommand(os.Args[1:])); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(usageText)
			return
		}
		fmt.Fprintln(os.Stderr, "netdir:", err)
		fmt.Fprintln(os.Stderr, "try: netdir --help")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println("netdir v" + version())
		return
	}

	// pre-v15 installs kept the config in /etc/liras: bring it over once, and never
	// use that location again, even if an old service unit still names it
	if *conf == legacyConfPath {
		fmt.Fprintf(os.Stderr, "netdir: %s is no longer used; using %s (update the service unit's --config, or re-run install.sh)\n", legacyConfPath, confPath)
	}
	*conf = canonicalConf(*conf)
	if *conf == confPath && os.Geteuid() == 0 {
		if moved, err := migrateLegacyConfig(confPath, legacyConfPath); err != nil {
			fmt.Fprintf(os.Stderr, "netdir: could not move %s to %s: %v\n", legacyConfPath, confPath, err)
		} else if moved {
			fmt.Fprintf(os.Stderr, "netdir: moved your configuration from %s to %s and removed the old files\n",
				legacyConfPath, confPath)
		}
	}

	switch {
	case *configure:
		if err := interactiveConfigure(*conf); err != nil {
			fatal(err)
		}
		return
	case *showNeigh:
		showNeighbors(*sock)
		return
	case *showGateways:
		showGatewayTable(*sock)
		return
	case *restoreFile != "":
		if err := runRestore(*restoreFile, *restorePwF, *stateDir, *conf, *sock); err != nil {
			fatal(err)
		}
		return
	case *backupNow:
		op(*sock, "backup.run", nil)
		fmt.Println("A backup has started on this node. See how it went with: netdir --backup-status")
		return
	case *backupStat:
		showBackupStatus(*sock)
		return
	case cli.run(*sock):
		return
	case *assertAGC:
		res := mustStatus(*sock, "assert-agc")
		if ok, _ := res["ok"].(bool); !ok {
			fmt.Printf("assert-agc failed: %v\n", res["error"])
			os.Exit(1)
		}
		for _, m := range res["messages"].([]any) {
			fmt.Println(m)
		}
		return
	}

	applyPendingRestore(*stateDir, *conf) // a restore that the GUI prepared and confirmed
	_, statErr := os.Stat(*conf)
	configExists := statErr == nil
	created := false
	dc, err := loadConfig(*conf)
	if err != nil {
		fatalf("Configuration error: %v", err)
	}
	if *level != "" {
		dc.LogLevel = *level
	}
	if *showConfig {
		b, _ := json.MarshalIndent(dc, "", "  ")
		fmt.Println(string(b))
		return
	}

	if configExists {
		if err := dc.Validate(); err != nil {
			fatalf("Configuration error: %v", err)
		}
	} else {
		// Absent config: write one with the defaults and no gateways, then start.
		dc.Groups = []GroupConfig{}
		if err := dc.save(*conf); err != nil {
			fatalf("cannot create %s: %v", *conf, err)
		}
		created = true
	}

	setupLogging(dc.LogLevel)
	startLogFile(*stateDir)
	if !created {
		infof("netdir starting — %d group(s)", len(dc.Groups))
	} else {
		infof("netdir starting — config file %s not found, created it with the defaults", *conf)
	}
	if err := run(dc, *conf, *sock, *stateDir); err != nil {
		fatal(err)
	}
}

func run(dc *DaemonConfig, confFile, sockPath, stateDir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// kill -USR1 writes every goroutine's stack to the log (the journal): the way to see what a daemon that is up but not
	// answering is stuck on, when its own pages and the troubleshooting bundle cannot be reached
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-usr1:
				warnf("SIGUSR1: every goroutine's stack is written to standard error (journalctl -u netdir)")
				fmt.Fprintf(os.Stderr, "--- goroutine dump (SIGUSR1) %s ---\n%s--- end of goroutine dump ---\n", time.Now().Format(time.RFC3339), goroutineDump())
			}
		}
	}()

	// the path of the running binary, taken before any update can replace it
	exe, _ := os.Executable()
	exe = strings.TrimSuffix(exe, " (deleted)")

	mg, err := NewMgmt(confFile, stateDir, dc)
	if err != nil {
		return err
	}
	mg.upd.exePath = func() (string, error) { return exe, nil }
	if mg.upd.GuardOnStart() { // the previous update never stayed up: back to the old binary
		warnf("restarting into the restored previous version")
		return syscall.Exec(exe, os.Args, os.Environ())
	}
	if n := mg.upd.RolledBackNotice(); n != "" {
		warnf("update: %s", n)
	}
	var reexec atomic.Bool
	mg.restartFn = func() { reexec.Store(true); stop() }

	// the saved host history comes back at start; the last save happens when the daemon stops
	savedStats := startPersistence(stateDir, ctx.Done())

	sup := NewSupervisor(ctx, dc)
	sup.StartAll()
	go applySNMP(dc.snmpSettings())
	go snmpRefresh(ctx, sup)
	go applyLLDP(dc.Settings.LLDP)
	go lldpWatch(ctx, sup)
	go memguard.Run(ctx.Done())
	go devHealth.Run(ctx, sup.deviceInventory)
	go mg.sched.Run(ctx)

	st := NewStatusServer(sockPath, sup)
	st.mg = mg
	mg.gwIPsFn = func() []string {
		var out []string
		seen := map[string]bool{}
		for _, r := range st.snapshot() {
			if r.Local && r.PeerIP != "" && !seen[r.PeerIP] {
				seen[r.PeerIP] = true
				out = append(out, r.PeerIP)
			}
		}
		sort.Strings(out)
		return out
	}
	mg.gwFn = func() []GwState {
		cfg, snap := sup.config(), st.snapshot()
		gs := gatewayStates(cfg, snap)
		// each gateway's health as this node's own drawing colours it, so the other nodes can show it too
		groups := buildCanvas(cfg, snap)
		markOffnet(groups, sup.offnetGroups())
		off := sup.offnetGroups()
		for i := range gs {
			_, gs[i].Offnet = off[gs[i].GroupID]
			for _, g := range cfg.Groups { // removed from the gateway: it can never serve it either
				if g.GroupID == gs[i].GroupID && containsStr(g.ExcludedNodes, localNodeID()) {
					gs[i].Offnet = true
				}
			}
			for _, g := range groups {
				if g.GroupID == gs[i].GroupID {
					gs[i].Health, gs[i].HealthWhy = g.Status, g.Detail
				}
			}
		}
		return gs
	}
	mg.pausedFn = func() bool { return sup.config().NodePaused }
	mg.anycastFn = sup.AllAnycastStates
	mg.tshootFn = func() map[string]any {
		return map[string]any{"canvas": st.canvasGroups(), "gateway-snapshot": st.snapshot()}
	}
	host, _ := os.Hostname()
	ae := NewAlertEngine(stateDir, host, func() *AlertsConfig { return sup.config().Settings.Alerts })
	ae.st, ae.mg, ae.sample = st, mg, ae.sampleNode
	mg.alerts, st.alerts = ae, ae
	go ae.Run(ctx)
	be := NewBackupEngine(stateDir, confFile, host, func() *BackupConfig { return sup.config().Settings.Backup })
	be.scheduled = func() bool { return backupScheduled(sup.config().Settings.Schedule, localNodeID()) }
	mg.backup = be
	go be.Run(ctx)
	if err := st.Start(); err != nil {
		warnf("status socket unavailable (%s): %v — --show-* commands will not work", sockPath, err)
	}

	var web *WebServer
	reload := func() error {
		nu, err := loadConfig(confFile)
		if err == nil {
			err = nu.Validate()
		}
		if err != nil {
			warnf("Config reload skipped — %v", err)
			return err
		}
		infof("Config file changed — reloading")
		sup.Reload(nu)
		go applySNMP(nu.snmpSettings())
		go applyLLDP(nu.Settings.LLDP)
		mg.OnConfigLoaded(nu)
		if web != nil {
			go web.mcp.reconcile()
			go func() { ensureReadGroup(nu.Web); web.Apply(nu.Web) }() // async: a listener restart must not wait on the request that triggered it
		}
		return nil
	}
	mg.reloadFn = reload
	web = NewWebServer(mg, st, sysAuth{})
	mg.webH = web.Handler()
	ensureReadGroup(dc.Web)
	web.Apply(dc.Web)
	defer web.Stop()
	web.mcp.Start()
	defer web.mcp.Stop()
	mg.OnConfigLoaded(dc) // first history entry, cluster listener
	defer mg.cl.Stop()
	go mg.cl.Run(ctx)
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(bootConfirmAfter):
			mg.upd.GuardConfirm(mg.cl.selfAddrForEvents())
		}
	}()
	go certExpiryWatch(ctx, mg)
	w := NewConfigWatcher(confFile, func() { reload() })
	if err := w.Start(ctx); err != nil {
		warnf("config watch unavailable: %v — edits need a restart", err)
	}

	infof("netdir running — %d group(s), watching %s", len(dc.Groups), confFile)
	if cpuProcs > 0 {
		infof("CPU limit of %.2f in this cgroup: using %d scheduler threads instead of %d", cpuQuota, cpuProcs, runtime.NumCPU())
	}
	if memLimit > 0 {
		infof("memory: garbage collector soft limit %d MiB", memLimit>>20)
	}
	<-ctx.Done()
	infof("Shutdown signal received")
	st.Stop()
	done := make(chan struct{})
	go func() { sup.StopAll(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		warnf("shutdown timed out")
	}
	savedStats()
	if reexec.Load() {
		web.Stop()
		mg.cl.Stop()
		infof("re-executing %s", exe)
		return syscall.Exec(exe, os.Args, os.Environ())
	}
	return nil
}

// certExpiryWatch logs a warning at start and then daily when the GUI
// certificate has expired or is about to.
func certExpiryWatch(ctx context.Context, mg *Mgmt) {
	for {
		if w := mg.certs.ExpiryWarning(); w != "" {
			warnf("web: %s — replace it under Configure ▸ Web GUI or with netdir --tls-install", w)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func fatal(err error)           { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

// ── CLI views ────────────────────────────────────────────────────────────────

func mustStatus(sock, cmd string) map[string]any {
	res, err := statusRequest(sock, map[string]any{"cmd": cmd})
	if err != nil {
		fatal(err)
	}
	return res
}

func decodeData(res map[string]any, v any) {
	b, _ := json.Marshal(res["data"])
	json.Unmarshal(b, v)
}

func showNeighbors(sock string) {
	var rows []SnapshotRow
	decodeData(mustStatus(sock, "snapshot"), &rows)
	peers := peersOnly(rows)
	if len(peers) == 0 {
		fmt.Println("No neighbors.")
		return
	}
	const f = "%-8s %-5s %-42s %-5s %-5s %-7s %-13s %s\n"
	fmt.Printf(f, "GROUP", "AF", "PEER IP", "PRI", "AFN", "WEIGHT", "HELLO avg/max", "STATE")
	fmt.Println(strings.Repeat("-", 90))
	for _, p := range peers {
		state := p.State
		if p.Preempt {
			state += " preempt"
		}
		fmt.Printf(f, itoa(p.GroupID), p.AF, p.PeerIP, itoa(p.Priority), itoa(p.AfnID),
			itoa(p.Weight), helloText(p.HelloAvgMS, p.HelloMaxMS), state)
	}
}

func showGatewayTable(sock string) {
	var rows []SnapshotRow
	res := mustStatus(sock, "snapshot")
	decodeData(res, &rows)
	groups := buildGateways(rows)
	ipNames := map[string]string{}
	if nm, ok := res["names"].(map[string]any); ok {
		for ip, n := range nm {
			ipNames[ip], _ = n.(string)
		}
	}
	nameMembers(groups, ipNames)
	if len(groups) == 0 {
		fmt.Println("No gateway groups.")
		return
	}
	names := map[int]string{}
	if res, err := statusRequestTimeout(sock, map[string]any{"cmd": "canvas"}, 10*time.Second); err == nil {
		var cg []CanvasGateway
		decodeData(res, &cg)
		for _, c := range cg {
			names[c.GroupID] = c.Name
		}
	}
	for _, g := range groups {
		title := fmt.Sprintf("Group %d", g.GroupID)
		if n := names[g.GroupID]; n != "" {
			title = fmt.Sprintf("%s (group %d)", n, g.GroupID)
		}
		fmt.Printf("%s  VIP %s\n", title, g.VIP)
		fmt.Printf("%-18s %-40s %-5s %-5s %-7s %-8s %-10s %-13s %s\n", "NODE NAME", "NODE IP", "PRI", "SLOT", "WEIGHT", "ROLE", "STATE", "HELLO avg/max", "VMAC")
		fmt.Println(strings.Repeat("-", 113))
		for _, m := range g.Members {
			hello, flag := helloText(m.HelloAvgMS, m.HelloMaxMS), ""
			if m.Local {
				hello, flag = "(local)", " *"
			}
			fmt.Printf("%-18s %-40s %-5d %-5d %-7d %-8s %-10s %-13s %s\n", orDefault(m.Name, "-")+flag, m.IP, m.Priority,
				m.Slot, m.Weight, m.Role, strings.ToUpper(m.State), hello, orDefault(m.VMAC, "-"))
		}
		fmt.Println()
	}
	fmt.Println("* = this node")
}

// ── Interactive configure ────────────────────────────────────────────────────

type prompter struct{ r *bufio.Reader }

func (p *prompter) ask(label, cur string) string {
	fmt.Printf("  %s [%s]: ", label, cur)
	s, _ := p.r.ReadString('\n')
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return cur
}

func (p *prompter) askInt(label string, cur int) int {
	for {
		v, err := strconv.Atoi(p.ask(label, strconv.Itoa(cur)))
		if err == nil {
			return v
		}
		fmt.Println("    please enter a number")
	}
}

func yes(s string) bool {
	switch strings.ToLower(s) {
	case "yes", "y", "true", "1":
		return true
	}
	return false
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func interactiveConfigure(path string) error {
	dc, err := loadConfig(path)
	if err != nil {
		return err
	}
	p := &prompter{bufio.NewReader(os.Stdin)}
	fmt.Println("Distributed Gateway Interactive Configuration")
	fmt.Printf("Config file: %s\nPress Enter to keep current value.\n\n", path)

	dc.LogLevel = p.ask("Log level (debug/info/warning/error)", dc.LogLevel)
	fmt.Printf("\nCurrently %d group(s) configured.\n", len(dc.Groups))
	n := p.askInt("How many groups?", len(dc.Groups))
	for len(dc.Groups) < n {
		g := newGatewayGroup()
		g.GroupID = firstGroupID + len(dc.Groups)
		dc.Groups = append(dc.Groups, g)
	}
	if n < len(dc.Groups) && n >= 0 {
		dc.Groups = dc.Groups[:n]
	}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		fmt.Printf("\n  Group %d\n", i+1)
		g.GroupID = p.askInt("Group ID (1-255)", g.GroupID)
		g.Interface = p.ask("Interface", g.Interface)
		g.VIP4 = blankable(p.ask("IPv4 VIP/prefix (e.g. 10.0.0.1/24, '-' to disable)", orDash(g.VIP4)))
		g.VIP6 = blankable(p.ask("IPv6 VIP/prefix (e.g. 2001:db8::1/64, '-' to disable)", orDash(g.VIP6)))
		g.Priority = p.askInt("Priority (0-255)", g.Priority)
		g.HelloMS = p.askInt("Hello interval ms", g.HelloMS)
		g.HoldMS = p.askInt("Hold time ms", g.HoldMS)
		g.MaxAFNs = p.askInt("Max active forwarders (1-255)", g.MaxAFNs)
		fmt.Println("    LB methods: roundrobin, weighted, hostpinned, failover")
		for {
			m, err := parseLB(p.ask("LB method", g.LBMethod.String()))
			if err == nil {
				g.LBMethod = m
				break
			}
			fmt.Println("   ", err)
		}
		g.Weight = p.askInt("Weight (weighted mode)", g.Weight)
		g.Preempt = yes(p.ask("Preemption enabled? (yes/no)", yn(g.Preempt)))
		g.RealMACs = yes(p.ask("Use real MAC addresses instead of virtual MACs? (yes/no; for VMware port groups that are not promiscuous or clouds that allow one MAC per interface)", yn(g.RealMACs)))
		g.Key = p.ask("HMAC-SHA256 shared key", g.Key)
	}
	if err := dc.Validate(); err != nil {
		return fmt.Errorf("not saved: %w", err)
	}
	if err := dc.save(path); err != nil {
		return err
	}
	fmt.Printf("\nConfiguration saved to %s\n", path)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func blankable(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// helloText is a peer's measured hello gaps as "average/largest" in ms, "-" before two hellos have arrived.
func helloText(avg, max int64) string {
	if avg <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", avg, max)
}
