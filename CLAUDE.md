# Instructions for Claude working on this project

MCP Network Director (`netdir`) is a Go daemon: the Distributed Gateway Load Balancing Protocol (VIP
shared by an AGC and AFNs through per-node virtual MACs, plus anycast addresses over BGP/OSPF) carrying an
MCP endpoint (`/mcp`, its own HTTPS listener on every gateway address, port 443; the GUI is not served there) that reaches the network's switches and firewalls through the
drivers in `source/device/` (one file per platform: `iosxe.go`, `ios.go` (classic IOS over SNMP, with `snmp.go`: BER, v2c, v3), `sdwan.go`, `nsxt.go`, `aci.go`, `nxos.go`, `eos.go`, `aoscx.go`, `fortios.go`, `panos.go`, `nios.go`, `technitium.go`, `bigip.go`, `director.go` (dnsdir, ntpdir and netdir) with `downstream.go` (a netdir device's own devices: the index and the requests passed down; the main package's `downstream.go` builds the index and routes), `meraki.go` and `meraki_write.go` (Cisco Meraki, Dashboard API), `entra.go` and `entra_signin.go` (Microsoft Entra ID, Graph, read only; browser sign-in), `afc.go` (Aruba Fabric Composer), `proxmox.go` (Proxmox VE), `pxmx.go`, `pbs.go` and `pdm.go` (Proxmox Backup Server and Datacenter Manager; shared parts in `pxmx.go`), `observium.go`, `ipfabric.go`, `aviatrix.go`, `centreon.go`, `junos.go` (Juniper Junos REST, with write), `vcenter.go` (VMware vCenter REST, with write), `nsone.go` and `rcode0.go` (NS1 and RcodeZero hosted DNS, REST, with write; shared parts in `dnsrest.go`) and also (Observium monitoring, REST API, read only); browser sign-in routes: `source/devsignin.go`; user troubleshooting (Entra → Meraki): `source/devtroubleshoot.go` with `device/clients.go` and `device/meraki_clients.go`; packet capture: `capture.go` (limits, pcap summary) and `capture_drivers.go` (directors, EOS, BIG-IP) with `source/devcapture.go`; device changes: typed ones are `change.go` with `iosxe_write.go`, `eos_write.go` and `aoscx_write.go` and `source/devchange.go`; arbitrary ones are `rawchange.go`, `rawrest.go`, `rawcli.go`, `rawpanos.go` and `source/devraw.go` with the guards each platform lists; both refuse read-only callers through the shared gate). It started as a fork of the
NTP Director; the NTP serving (chrony, pools, probing, query statistics) is gone. This file is a
standing instruction from the project owner so it doesn't need repeating each
conversation. If you (Claude) are asked to change this project, follow the
process below without being told to.

## Release process — do this for every request that changes the project

1. **Do the requested work** (code, docs, config, whatever was asked).
**Layout.** The tarball has `README.md` and `LICENSE` at the top, `docs/` (CHANGELOG.md), `source/` (the Go
module: `go.mod`, every `*.go`, `webui/`, `testdata/`, `netdir.conf.example`, and `VERSION`,
which must sit next to the Go files because `version.go` embeds it), `contrib/`, `install.sh`,
`get.sh` (the `curl | bash` web installer: fetches the latest tag from GitHub and runs its `install.sh`; keep it working with the tag/layout rules here),
`uninstall.sh`, `QUICKSTART.md` (a GUI-first getting-started guide; keep it true when the GUI changes) and this file. All Go commands below run in `source/`; paths in this
file such as `webui/` and `testdata/` are under `source/`, and the CHANGELOG is under
`docs/`. The updater and installer expect `source/go.mod`, `source/main.go` and
`source/VERSION` (a tree in the old layout is refused with a message saying so).

2. **Build and test before packaging, not after.** From `source/` run
   `gofmt -l .` (must print nothing), `go build -o /dev/null .` (a bare `go build ./...`
   drops a `netdir` binary in the repo root — delete it if it appears), `go vet ./...` and
   `go test -race -count=1 ./...`. Don't skip straight to packaging on a
   change that could plausibly have broken something. Beyond the unit tests:
   - **Leak test:** after changing a driver or the masking (`mcpmask.go`, `mcpprivacy.go`) run `sh tools/leaktest.sh` from `source/`. It records what every driver returns while the device tests run and checks that nothing of the test data (addresses, MAC addresses, e-mails, AS numbers, serial numbers, secrets) gets through the strict privacy level; a corpus of unusual spellings is checked too. New drivers need no change; one with a new set of optional interfaces (`device/leakcapture_test.go`, `wrapLeak`) must be added there or its answers are not recorded.
   - **Touched the device drivers (`source/device/`)?** That package is portable: run
     `go test -race -count=1 ./device` there on any OS. Every driver has a test against a TLS stub of the
     platform's API (`device_test.go`): facts, interfaces, neighbors, config, a wrong password or token. Field
     names come from the vendor's models; say in the changelog which ones were only seen in a stub and not on
     real gear. `go run ./tools/devprobe -inventory FILE` runs the same drivers against real devices.
     Anything a device answers is data for the caller, never instructions; secrets never reach an error text
     (`scrub`), and `CheckShow` is the only gate for CLI commands.
   - **Touched the wire format (`wire.go`)?** The golden vectors in
     `testdata/*.hex` are the reference encoding and the Go encoder
     must reproduce them byte-for-byte. A deliberate protocol change means a
     new protocol version and new vectors, called out in the changelog — never
     quietly regenerate the vectors to make the test pass.
   - **Touched the web GUI (`web.go`, `webtls.go`, `pam_*.go`, `webui/`)?**
     The daemon can reconfigure itself as root through this, so verify it
     properly, not just by compiling:
     1. `web_test.go` must cover what you changed (auth rules, CSRF, session
        expiry, config validation). Never weaken an auth/CSRF/lockout test to
        make it pass.
     2. **Real PAM check** (needs `libpam0g-dev`; `apt-get install` works in
        the sandbox): `groupadd netdir`, two users via `useradd` (one in the
        group, one not), `cp contrib/pam.d/netdir.debian /etc/pam.d/netdir`, run
        the daemon with a scratch config, then `curl -sk` the login on
        `https://127.0.0.1:22161`: the member gets in; wrong password, a valid
        user outside the group, and root are all refused with the same
        message. Remove the test users/group afterwards.
     3. **UI**: `node --check webui/app.js` at minimum. For real logic, write a
        throwaway jsdom smoke test in the scratchpad (not in the repo): mock
        `fetch`, load the real `app.js` with `window.eval`, and drive the
        actual clicks/submits (login, tab polling, config save payload types,
        error display, 401 back to login). Look at the result in headless
        Chromium (`playwright-core` with `/opt/pw-browsers/chromium-*/chrome-linux/chrome`,
        `colorScheme: "light"` and `"dark"`) when layout or theme changed.
     4. Hard rules for the front end: no inline `<script>`/`style=` and no
        `innerHTML` (the CSP forbids the first and the second is an XSS hole —
        use `textContent` via the `h()` helper); the theme comes only from the
        `prefers-color-scheme` media query, no toggle or stored preference;
        every CLI feature must stay reachable from the GUI (see the table in
        the README) — add the GUI side in the same change as any new CLI flag,
        and the other way round.
   - **Touched config history, cluster, certificates or updates
    (`configver.go`, `cluster*.go`, `shared.go`, `certmgr.go`, `update.go`,
    `mgmt.go`, `ops.go`, `cli.go`, `web_mgmt.go`)?** The in-process tests are
    necessary but were not enough: a live run found six real bugs they missed.
    So also run **two or three real daemons** from one scratch dir each
    (`--config ./netdir.conf --state-dir ./state --status-socket ./s.sock`,
    `"groups": []` keeps it idle, give each distinct `web.listen`/`cluster.listen`/
    `cluster.self` on 127.0.0.1, plus a
    throwaway PAM user as in the web check) and drive them through the CLI and
    the HTTPS API: join (`--yes --cluster-join`), a shared edit on a replica
    (must reach the primary and every node while per-node fields stay local),
    `--cluster-promote`, certificate install/revert (all nodes must serve it),
    versions (list/diff/restore), and an update: `--update-upload` a copy of the
    tree with a higher `VERSION`, then `--update-push all` — every node must
    build, re-exec and reach `guard.json` state `ok` (about 20 s per node; the
    build needs go, gcc and the PAM headers). Use *relative* paths for
    `--state-dir`/`--config` once: that once broke the build. The daemons share
    one `netdir` binary here, so the update rebuilds the file they all run — use
    a copy per node if that matters. Afterwards kill them, `ip link del
    netdir1.1` (a config with no `groups` key still creates a default group and a macvlan; `"groups": []` is really empty),
    remove the PAM user/group/`/etc/pam.d/netdir`. In the UI, look at the
    History/Certificate/Cluster/Updates tabs against a live daemon in
    Chromium (light and dark) and click through them: jsdom missed a null list
    and a nested-array render bug that Chromium showed immediately. JSON lists
    the GUI maps over must serialise as `[]`, never `null`.
  - **Touched `install.sh` / `uninstall.sh`?** They run as root on other
     people's machines, so: `bash -n` + `shellcheck -x -S warning` clean; a
     `--dry-run` per family using `NETDIR_OS_RELEASE` with fake os-release files
     (ubuntu, debian, linuxmint, fedora, rocky, almalinux, centos, arch,
     manjaro, endeavouros; alpine must be refused) plus
     `NETDIR_ASSUME_MISSING=gcc,pam,ip,tar,go,curl NETDIR_FORCE_GO_DOWNLOAD=1`
     (dnf needs a stub `dnf` in `PATH` on Debian-family sandboxes); then a real
     run in the sandbox with a shim `systemctl` (`NETDIR_SYSTEMCTL`,
     `NETDIR_FORCE_SYSTEMD=1`, `NETDIR_SETTLE=0`): fresh install, same-version
     no-op, upgrade (copy the tree, bump its VERSION), forced-failure
     rollback, downgrade refusal, uninstall with and without `--purge`, a
     customised PAM file surviving. Test the Go download against a local
     `python3 -m http.server` via `NETDIR_GO_BASE_URL` (go.dev is unreachable
     from the sandbox), including a wrong-checksum refusal. Undo every sandbox
     change afterwards (group, `/etc/pam.d/netdir`, `/var/lib/netdir`, `/run/netdir`, units).
     Never let the uninstaller delete a config/cert without `--purge`, or a
     PAM file/group it didn't create.
   - **Touched the Users page (`users.go`, `users_cli.go`, `/api/users`)?** These run
     `useradd`/`usermod`/`userdel`/`chpasswd` as root, so the unit tests (fake `usersRun`) are
     not enough: with a real PAM setup (as in the web check) add a user through the CLI, sign in
     as it over HTTPS, add/expire/re-password/delete another through the API, and check an
     expired account and an old password are refused. Names are validated before they reach a
     command, passwords go to `chpasswd` on stdin only, and only members of the GUI group can be
     changed. Every change is also sent to the other cluster nodes (`/cluster/users`, as the hash): check it
     with two daemons where the second runs in its own mount namespace with a private copy of `/etc`
     (`unshare -m`, `mount --bind etc2 /etc`), because on one host both would share one passwd file.
     Remove the test users, group and PAM file afterwards.
   - **Touched the node picker (`proxy.go`, `proxyPrefixes`, `LOCAL_API` in
     `app.js`, `/cluster/proxy`)?** A new `/api/` route is relayable only if its
     prefix is in `proxyPrefixes` (everything but login/logout/session is), and
     `LOCAL_API` in the JS must match; the picker's own node list is the one call
     made with `api(..., true)` (always the login node). Live-check two
     clustered daemons: pick the other node, change something, confirm the history
     actor reads `user via addr` on that node.
   - **Added/changed a page, a CLI flag or a setting?** Update `webui/help.js` (one
     topic per page, each with a "Command line" block); `TestEveryPageHasHelp` fails
     when a page has no topic. Live-check the "?" panel in Chromium (light and dark).
   - **Touched the start gates (`startGroupWhenReadyLocked`, `onGatewaySubnet`)?**
     A gateway starts only when this node has an address in its VIP subnet (v4; v6 if it has a global v6 address)
     (grey "not running here" otherwise, never counted as serving). Live-check with a VIP on a subnet eth0 is not in, then
     `ip addr add` one and watch it start.
   - **Touched `power.go` / the Power page?** The tests fake `powerRun`/`powerStart`;
     for a live check put fake `shutdown`/`systemctl` scripts first in the daemon's
     `PATH` (never reboot the sandbox) and drive the CLI and the page with them.
   - **Touched leave/handover, MAC takeover or the hello flags?** Unit tests are
     not enough here: a real two-node run found three bugs they missed (the
     switch keeping a MAC on its old port, a restarted node pulling the controller
     role back, a leaving node rebuilding its MAC). The sandbox can do it: a bridge,
     two network namespaces joined by veth pairs, one daemon per namespace
     (`ip netns exec`), a third namespace as client that pins the VIP's neighbour
     entry (`ip neigh replace … nud permanent`) to the restarting node's virtual MAC
     `00:1a:7c:<group>:<slot>:00` and queries the VIP every 100 ms while you
     SIGTERM and restart a node. Failures must stay ≈ 0 s for both a controller and
     a forwarder restart. (`ip netns` and bridges work; there is no `ping`.)
   - **Touched the MCP listeners (`mcplisten.go`, `noGatewayListener`, `settings.mcp_port`)?** One listener per gateway
     address, bound with IP_FREEBIND, serving `/mcp` only; the GUI refuses connections that arrive on a gateway address;
     `mcpServing` (not the GUI) decides whether anycast addresses are carried. The sandbox can bind a non-local v4 address
     (`192.0.2.x`) but has no IPv6, so the v6 bind is not verified here; say so in the changelog.
   - **Touched anycast addresses (`anycast.go`, `GroupConfig.ExtraVIPs`)?** They are
     independent of the election and must never restart a gateway (`restartDiffers`
     ignores them; `Reload` swaps them in place). Each is on `lo` with a 10 s lifetime
     renewed every 3 s, and is removed when the MCP listeners are not serving (`serviceUpFn`, health.go), the group
     stops/pauses, or netdir stops. Live-check (the sandbox has no IPv6, so only v4):
     `ip -4 addr show dev lo` shows it with `valid_lft 10sec`, a query to it is answered,
     stopping the MCP listeners withdraws it, `kill -9` removes it within ~10 s,
     SIGTERM at once; two clustered daemons (a gateway on a subnet the host is not
     on, so it only replicates) must agree after an edit on either.
   - **Touched BGP (`bgp.go`, `bgp_cli.go`, `VIEWS.anycast`/`VIEWS.anycastop`/`VIEWS.anycaststatus`)?** The settings are per node
     (never in `SharedConfig`), the config key is a pointer with `omitempty` so a config
     that never used BGP stays readable by older versions (they reject unknown keys), and
     every value that reaches `frr.conf` is validated (no injected lines). The sandbox can
     run the real thing: `apt-get install frr`, a fake `systemctl` first in the daemon's
     `PATH` mapping `restart|start|reload frr` to `/usr/lib/frr/frrinit.sh`, a veth pair to
     a network namespace running a peer `bgpd -n` (as user frr, config and run dir owned
     by frr), a gateway with an anycast address (a second FRR instance for the peer: `ip netns exec peer /usr/lib/frr/frrinit.sh start peer` with `/etc/frr/peer/{daemons,frr.conf,vtysh.conf}` owned by frr, `zebra`+`bgpd`+`bfdd` all on, and `no bgp ebgp-requires-policy` on the peer; BFD needs zebra). Check: session Established, BFD `up` at the peer, the peer
     receives the `/32`, a route the peer announces is NOT installed here, stopping the
     web listener or `kill -9` withdraws it at the peer within ~10 s, clearing the AS (`--asn off`) removes the
     section and the marker (give it ~10 s). Restore `/etc/frr/frr.conf` and `daemons` afterwards (back them up
     first), remove the namespace and veth.
   - **Touched engine stop/leave or controller election?** A stopping controller
     sends `pktResign` and the best remaining node becomes controller at once and
     takes over the old controller's vMAC (`takeOverControllerSlotLocked`); update
     restarts wait for `waitUntilSafe`. Keep the tests in `engine_test.go` passing.
   - **Touched the canvas (`canvas.go`, `VIEWS.topology`) or the shared `Settings` block?**
     The colours are computed once, in `buildCanvas` (GUI and `--canvas` both
     use it) — never re-derive status in JavaScript. Anything a form or the
     Settings page rebuilds from fields must carry the `settings` fields through
     untouched. A config with the old `ntp` block is refused on purpose
     (`DaemonConfig.UnmarshalJSON`), so nothing that still writes it can drop the settings. An explicit
     `"groups": []` must stay empty; only a *missing* key means the default group.
   - **Touched election/AFN logic?** Add or extend a test in `engine_test.go`
     (feed `onPacketLocked` crafted packets); this code has had a real bug
     (a higher-priority joiner stuck in SPEAK) that only such a test catches.
3. **Cross-compile every release**, not just once — a later change can
   silently break a platform nothing here runs. For each of `linux/amd64`,
   `linux/arm64`, `linux/arm`, `linux/386`, `linux/riscv64` run
   `GOOS=<os> GOARCH=<arch> go build -o /dev/null .`. netdir is Linux-only
   (macvlan, AF_PACKET, inotify); don't add other OSes. `linux/mips*` compiles
   but `SO_REUSEPORT` (hard-coded to 15 in `util.go`) is wrong there — don't
   list it as supported unless that constant is made per-arch first. If a new
   target is added, add it to this list in the same change.

   **cgo caveat (PAM):** the web GUI's PAM binding is cgo (`pam_linux.go`).
   Cross-compiles run with cgo off and so build the fail-closed stub
   (`pam_stub.go`): they prove the code compiles, not that a PAM build works,
   and a binary built that way will refuse to start the GUI. Only the native
   build (amd64 in the sandbox) is actually verified with PAM; say so in the
   changelog. Don't "fix" this with a `CGO_ENABLED=0` path that serves the GUI
   without PAM — the stub must keep failing closed. Also run
   `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...` so the stub path
   stays healthy.
4. **Bump `VERSION`.** It's a single plain integer (no `v` prefix, no semver)
   at `source/VERSION`, embedded into the binary (`version.go`,
   `netdir --version`). Increment it by exactly 1 (the numbering restarted at 1 for netdir). `TestVersionIsPlainInteger`
   fails if the file is malformed — fix the file, don't weaken the test.
5. **Append a new entry to the top of `docs/CHANGELOG.md`**, immediately below the
   `# Changelog` header (and any `## [Unreleased]` line), in the style of the
   existing entries (the history before v1 was removed on purpose; v1 is the first entry): `## [vN] - YYYY-MM-DD — <short summary>` where `N` is the
   new VERSION and the date is the date of the change, then `### Added` /
   `### Fixed` / `### Changed` sections as appropriate, plus `### Verified`
   and `### Not verified`. Say what changed, why, and exactly what was run.
   Do not rewrite or renumber older entries.
   New gateways are numbered from 161 (`firstGroupID`); keep tests that build a config by hand on explicit group numbers.
6. **Repackage the whole project into a `.tgz`** named `netdir_v<VERSION>.tgz`
   with the project directory itself (`netdir/`) at the top of the archive, so it
   re-extracts to `netdir/`. Source only: no built binaries, no scratch files,
   no `.tmp` leftovers (check `tar tzf` before handing it back).
7. **Hand the `.tgz` back** as the deliverable. Don't just describe the
   changes — the person expects a fresh archive every time, without having to
   ask.

Do steps 4–5 after every other file change (including this file and the
README), so the version and changelog describe the final tree.

## Notes

- **NO BANNERS. Ever.** Never add a banner, notice bar or status message line to the GUI: not for
  progress ("Scanning…"), not for success ("Saved", "finished"), not for info or warnings. State goes
  in the control itself (tooltip, button label, a few words of small text beside it, a row's colour).
  Do not call `say(status, "info"|"warn", …)` in new code. Not even a red one: no box, no bar, no background,
  no border. A failure the person must act on is plain red text (no box) beside the control that failed, and nothing else. When touching a page, remove any banner you find
  in the code you are changing. The owner has repeated this many times; do not make him say it again.

- **No update or status text between cards.** Never put a line of update/progress/status text in the gap between two cards on a page (e.g. "This node is holding back its queued update…"). Anything of that kind goes inside a card, in a control's tooltip or state, or in `webui/help.js`.

- **GUI text: keep it short.** Don't add explanatory paragraphs, hints or notes to pages, forms or tables.
  If something needs explaining, put it in `webui/help.js` (the "?" panel) and nothing on the page itself.
  A label, a placeholder and at most a few words of hint are the limit. Don't add any text the owner didn't ask for.

- **Field descriptions: one line, never longer than the field.** The text under a form field (its `hint`, and the range line `rangeHint` draws under a number field) is one line and no wider than the field it sits under, about 40 characters, e.g. `Host or host:port.` or `10 to 600 s. Default 30.` Nothing longer, nothing that wraps (`.f .hint` is `nowrap`, so a longer one is cut off). The full explanation goes in `webui/help.js`. `TestFieldHintsAreShort` fails a longer hint. The same holds for the notes under a section heading.

- The process applies to substantive changes (features, fixes, docs,
  refactors). Pure Q&A that changes nothing on disk needs no version bump.
- A pure packaging fix (archive name, permissions, directory layout) that
  changes nothing in the project's code, tests or behavior doesn't need a bump:
  note it under the current version's changelog entry in a short
  `### Packaging fix` subsection and keep the archive name matching.
- If a request is big enough to split into several changelog-worthy pieces in
  one sitting, one bump and one entry covering all of it is fine, and one
  `.tgz`.
- Keep changelog entries specific about what was built or fixed and why, and
  honest about what wasn't verified. The hardest parts of this project to
  verify — multi-host election on a real wire, ARP/NS steering to vMACs, an
  AFN answering for the VIP through `lo` + `arp_ignore` — can't be exercised in
  the sandbox; say "not verified" rather than implying they were.
- Dependencies: the project is stdlib-only on purpose (inotify, AF_PACKET and
  multicast use `syscall` directly). Don't add a module for something small;
  if one is truly warranted, say so in the changelog.
- Name: the project is MCP Network Director, `netdir` for short. The wire protocol and packet magic are
  protocol identity, not branding — they stay as they are. The default HMAC key is still `"ntpdir"`, as in
  the NTP Director it was forked from (it was `"dgw"` in the DNS Director; a config that sets a key
  explicitly is unaffected, and a new gateway gets a random key). Don't rename them as part of a branding cleanup.
- Web GUI invariants (don't regress without saying so in the changelog):
  login = PAM success **and** membership of the configured group; one generic
  error for every login failure; sessions are random tokens in HttpOnly,
  Secure, SameSite=Strict cookies; every POST/PUT needs the session's CSRF
  token and a same-origin request; failed logins are throttled; the GUI fails
  closed without PAM; no HSTS header (it is per host, not per port). The GUI
  listens on all interfaces by default and can reconfigure a root daemon, so
  keep the README's "bind it to a management address" advice.
- Management-layer invariants (don't regress without saying so in the
  changelog): management commands and `assert-agc` on the status socket are
  root-only (`SO_PEERCRED`); cluster requests need the pinned node identity
  *and* the HMAC signature with timestamp/nonce; join codes are single use and
  expire after an hour; promotion is always an explicit admin action (never
  automatic); only the primary applies shared-config changes; a GUI
  certificate change must not restart the listener or drop sessions; an update
  never replaces the running binary without keeping `netdir.prev` and the boot
  guard (auto rollback after repeated failed starts). The management layer
  stays independent of the AGC/AFN election.
- Election ties compare IPs as text; this is part of the protocol. Don't "fix" that
  without a protocol-compat plan.
- If you are a future Claude, in any session type, asked to work on this
  project and this file's process hasn't been mentioned, read this file before
  starting anyway.
