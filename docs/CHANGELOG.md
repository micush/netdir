# Changelog

## [v224] - 2026-11-18 — SNMP community strings kept from an assistant under the plural names too

### Fixed
- A key such as `snmp_communities`, `snmp-communities` or `snmpCommunities` was not recognised as holding secrets: the rules looked for the word `community`, and `communities` does not contain it, so the community strings came back in plain text in a device's configuration or answer. The rules now look for `communit`, in the key-name check, the JSON-text check and the line check, and also hide `ro_community`, `rw_community`, `read_community` and `write_community`. A BGP community (`bgp_communities`, a route-map line) is still shown: only a key under an SNMP name, or one of those names, is hidden.
- A list of plain values under a secret's name (`"radius_passwords": ["a", "b"]`) was shown as it was; it is now hidden whole, as an object of plain values already was.

### Verified
- `TestSNMPCommunitiesAreHidden` and `TestListUnderSecretNameIsHidden`; gofmt, vet, the device package tests, the redaction, privacy and leak tests of the main package, the leak test script.

### Not verified
- The exact shape of the four switches' configuration that leaked: I did not see it, so the fix covers the names above, not whatever the real field was called. If a community still shows, add its field name under Configure ▸ Privacy ▸ Secret words and tell me the name.

## [v223] - 2026-11-18 — the Topology filter matches a platform by its key as well as its name

### Fixed
- The Topology page's device filter looked at a platform only by its display name (`Cisco IOS-XE`), so `iosxe` found nothing. It now matches both, as the two Devices filters do.

## [v222] - 2026-11-18 — Configure ▸ Devices filter matches a platform by its name as well as its key

### Fixed
- The Configure ▸ Devices table filter looked in the Platform column only by its key (`iosxe`), so `IOS-XE` or `Cisco IOS-XE`, the name the column shows, found nothing. It now matches both.

## [v221] - 2026-11-18 — Add device ▸ Devices from inventory filters on platform, address and tags too

### Changed
- The filter box under the **Devices** list of Add device ▸ *Devices from inventory* matched only the device name. It now matches the name, the platform (its key, `proxmox`, and its name, `Proxmox VE`), the address and the tags, with the same AND, OR and `!` rules.

### Verified
- `node --check` of `app.js` and `help.js`; the device package builds.

### Not verified
- The filter in a real browser.

## [v220] - 2026-11-18 — the sensor check is removed: only monitoring and management systems show a purple alert square

### Removed
- The sensor-fault check of v218. A device that is not a monitoring or management system is never asked for its fans, power supplies or temperatures to colour its square, so the health check sends such a device nothing beyond the facts request it always did (no extra RESTCONF, REST or SSH requests on a switch, firewall or server).
- The purple square stays for Observium, Centreon, Aruba Fabric Composer, Aviatrix Controller and CoPilot, Panorama, Meraki, Unimus, Proxmox VE, vCenter, Proxmox Backup Server and Proxmox Datacenter Manager (their own alerts, at most every 2 minutes), and the option `alerts=off` still keeps one of them from ever being purple.

### Verified
- gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, the cross-compiles.

### Not verified
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard` (no PAM headers in this sandbox).

## [v219] - 2026-11-18 — Edit ▸ Arrange puts a gateway's devices in alphabetical order

### Added
- Right-click a gateway on the Topology page ▸ **Edit ▸ Arrange**: the gateway's devices (`devices`, the order of the squares) are sorted alphabetically, ignoring case, with numbers in names counted as numbers (sw2 before sw10). It is saved with the gateway like a drag. Greyed out, with the reason, when the gateway has fewer than two devices or they are in order already.

### Verified
- The sort run on sample names (case, numbers, already-sorted); `node --check` of `app.js` and `help.js`; the main package's help tests; gofmt, vet, the leak test, the five cross-compiles.

### Not verified
- The menu item in a real browser, and the native cgo/PAM build with `TestUpdateBuildApplyAndRollbackGuard` (no PAM headers in this sandbox).

## [v218] - 2026-11-18 — the purple alert square for every device: sensors in a fault state; `alerts=off`

### Added
- Every device whose driver reads resources and is not one of the monitoring or management systems above is purple while one of its sensors (fans, power supplies, temperatures) is in a fault state: the state says failed, fault, critical, alarm, error, warning, shutdown, bad, not ok or non-operational. An empty slot (absent, not inserted, not present) and an unknown state are not faults. Faults only: no CPU, memory or disk thresholds and no interfaces that are down. The count is taken when the device's facts are asked (every 5 minutes while someone looks, every 6 hours otherwise, and at once when someone starts looking), one more resources request then; a request that fails keeps the last count.
- The device option `alerts=off` (Options in the device form) keeps any one device, of any platform, from ever being purple.

### Verified
- `TestSensorFault` (the state words) and `TestMonitorCountsSensorFaults` (a fake driver with five sensors: two faults counted, an empty slot and a sensor with no state not; `alerts=off` gives none). gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, the five cross-compiles.

### Not verified
- The state words each real driver gives (read from the drivers' code and tests: aoscx, eos, nxos, iosxe, fortios, panos, nios) on real hardware; a word that is not in the list above never counts.
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard` (no PAM headers in this sandbox); the purple square in a real browser.

## [v217] - 2026-11-18 — the purple alert square for Proxmox Backup Server and Datacenter Manager

### Added
- **pbs**: datastores that report an `error` or are 90% full or more (`/status/datastore-usage`), and tasks of the last 24 hours that failed (`/nodes/localhost/tasks?errors=1`; a task that ended with warnings, one that is still running and an older failure are not alerts, so the square clears by itself).
- **pdm**: remotes Datacenter Manager cannot reach and nodes it counts as offline (`/resources/status`: `failed_remotes_list` or `failed_remotes`, `pve_nodes` and `pbs_nodes` with `offline`).

### Verified
- `TestActiveAlertsOfTheManagementPlatforms` covers both against the TLS stub (a full datastore, a failed task of the last hour, and a warning, an old failure and a success that are not counted; a failed remote and an offline node). The leak test records their alerts. gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, the five cross-compiles.

### Not verified
- Against a real Backup Server or Datacenter Manager. The fields of the PBS usage and task lists (`error`, `used`, `total`, `starttime`, `endtime`, `status`) are those of its API documentation; the `/resources/status` fields of Datacenter Manager (`failed_remotes`, `failed_remotes_list`, `pve_nodes.offline`) are from memory of its dashboard and may differ, in which case the square stays green.
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard` (no PAM headers in this sandbox); the purple square in a real browser.

## [v216] - 2026-11-18 — the purple alert square for Meraki, Unimus, Proxmox VE and vCenter

### Added
- The purple "alert" square (count in the tooltip) is also drawn for:
  - **meraki**: devices the dashboard reports `offline` or `alerting` (the organization's devices; with the option `serial`, that one). Dormant devices are not alerts.
  - **unimus**: managed devices whose last job (backup) failed (`lastJobStatus`), and the server itself when `/health` is not OK (with the option `device`, that device).
  - **proxmox** (Proxmox VE): cluster nodes that are not online (`/cluster/status`) and storages whose status is not `available` (`/cluster/resources?type=storage`).
  - **vcenter**: ESXi hosts whose `connection_state` is not CONNECTED, and parts of the appliance whose health (`/appliance/health/...`) is yellow, orange or red. vCenter's REST API has no alarms, so what the Alarms view shows is not counted; a host in maintenance mode is connected.
- Not for Proxmox Backup Server and Datacenter Manager (pbs, pdm).

### Verified
- `TestActiveAlertsOfTheManagementPlatforms` now covers meraki, unimus, proxmox and vcenter against the TLS stubs (the stubs of Unimus and Proxmox gained a failed backup, an offline node and an unavailable storage). `wrapLeak` records their alerts (leak test). gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, the five cross-compiles.

### Not verified
- Against real systems. Meraki's `status` values and Proxmox's `online` and storage `status` are the documented ones; Unimus's `lastJobStatus` is the field its device list is said to carry (a Unimus without it never shows a device alert); vCenter's health words are those the driver already reads.
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard` (the PAM headers could not be installed in this sandbox); the purple square in a real browser.

## [v215] - 2026-11-18 — the purple alert square for Aruba Fabric Composer, Aviatrix Controller and CoPilot and Panorama; the tooltip gives the count only

### Added
- The purple "alert" square of v214 (Observium, Centreon) is also drawn for these platforms, with the count in the tooltip:
  - **afc** (Aruba Fabric Composer): the alarms in `GET /alarms` that are not acknowledged, cleared or closed. An AFC with no such resource answers 404, which is an error (what was known is kept), never an alert.
  - **aviatrix** (Controller): the gateways of `list_vpcs_summary` that are not working: `inst_state` other than `running`, or a `gw_state` or `vpc_state` that says down, failed, error, stopped or unreachable. A gateway stopped on purpose counts.
  - **aviatrixcopilot** (CoPilot): gateways and tunnels that are down or degraded and BGP neighbors that are not established, from the status API the driver already reads.
  - **panorama** (platform *panorama* only): the managed firewalls `show devices all` reports with `connected` no. A *panos* firewall is never asked.

### Changed
- The tooltip of an alert square gives the count only (`Observium: 12 alerts`), and so does the detail line; the alerts themselves are no longer kept (`Health.Alerts` is gone, `alert_count` stays). The drivers still return them (`AlertReporter`) for tests.

### Verified
- `TestActiveAlertsOfTheManagementPlatforms` (afc, aviatrix, copilot, panorama with and without a disconnected firewall) and the Observium and Centreon tests against the TLS stubs; `TestCanvasDeviceWithAlerts`. `wrapLeak` records the alerts of every driver that has them (leak test). `node --check` of `app.js` and `help.js`. gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, the five cross-compiles.

### Not verified
- Against a real AFC, Aviatrix Controller, CoPilot or Panorama. The AFC resource `/alarms` and its fields (`acknowledged`, `cleared`, `state`, `description`) are not from a published reference I could read, and the Controller's `gw_state` and `vpc_state` are guesses next to the `inst_state` the driver already reads: if a real one names them differently the square simply stays green (AFC) or only `inst_state` counts (Controller). The CoPilot and Panorama fields are those the drivers already read.
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard` (the PAM headers could not be installed in this sandbox).
- The purple square and tooltip in a real browser.

## [v214] - 2026-11-18 — Observium and Centreon alerts: a purple square and the count in the tooltip; Open on devices

### Added
- Replaces the amber of v213: a device on the Observium or Centreon platform that answers and holds alerts is drawn **purple** on the Topology page (new status `alert`, a device colour only: not red, amber or green, because a monitoring system with alerts is working). The tooltip gives the count and the first 20 alerts (`Observium: 12 alerts`, `• host: check: message`, `… and 3 more`); the detail line names the first three. The legend has a purple "alerts" dot, `--canvas` prints `[ALRT]`. A device that is down stays red and one that refuses its request stays amber, whatever it holds. Nothing else changes: the Devices page, the alerts and the metrics still see it as `ok` (answering).
- Observium: the alerts are the failed ones (`/alerts/?status=failed`), for the server every monitored device's, with the option `device` that device's; the check names come from `/alert_checks/` and the host names from `/devices/` (both best effort).
- Centreon: the problems nobody has dealt with: hosts down or unreachable and services in warning, critical or unknown, except those acknowledged or in downtime. Only the first 20 pages of hosts and of services are read.
- `device.AlertReporter` (an optional driver interface, `ActiveAlerts`); `Health.Alerts` (first 20), `Health.AlertCount` and `Health.AlertsAt`. The monitor asks a driver of `alertPlatforms` (observium, centreon) at most every 2 minutes, on a reach check; a request that fails keeps what was known (a hiccup in the alert API is not an alert), and a device that is down forgets its alerts.
- Right-click a device on the Topology page ▸ **Open** (first item): opens `https://address[:port]` in a new browser tab (Observium below its `prefix` option). Not offered for ios, linux, windows, ad or tools, which have no web page. The browser makes the connection, not netdir.

### Verified
- `TestObserviumActiveAlerts`, `TestMonitorObserviumAlertIsAmber` (stays `ok`, count, detail), `TestCentreonActiveAlerts` (hosts and services) against the TLS stubs; `TestCanvasDeviceWithAlerts` (alert only when `ok`; a down device stays red). `wrapLeak` records the new alerts answer (leak test passes). `node --check` of `app.js` and `help.js`. gofmt, vet, `go test -race ./device`, the leak test, the main package's tests with cgo off, and the amd64, arm64, arm, 386 and riscv64 cross-compiles.

### Not verified
- The native cgo/PAM build and `TestUpdateBuildApplyAndRollbackGuard`: the PAM headers could not be installed in this sandbox, so that test (it builds the tree with cgo) fails here; nothing in it touches this change.
- Against a real Observium or Centreon: the alert fields (Observium `alert_status` 0 = failed, `alert_test_id`, `last_message`; Centreon `acknowledged`, `in_downtime`, `status.code`) are those the drivers already read, seen only in the stubs. If a build names them differently the alerts still count, but the text falls back to `entity_type entity_id alert` (Observium).
- The purple square, the legend and the tooltip, and the Open item, in a real browser (light and dark).

## [v213] - 2026-11-18 — an Observium alert turns its square amber

### Added
- A device on the Observium platform turns amber (`warn`) on the Topology page while Observium holds a failed alert, and the tooltip names the alerts. `device.AlertReporter` (an optional driver interface) and `Health.Alerts`. Superseded in v214, which paints such a square purple instead and adds Centreon.

### Verified
- Observium alert tests against the TLS stub, gofmt, vet, `go test -race ./device`.

### Not verified
- Against a real Observium; the native cgo/PAM build.

## [v212] - 2026-11-17 — the filter box of Add device ▸ Devices from inventory filters

### Fixed
- The filter box added in v208 did nothing: it read its text from the wrong element (the box's wrapper, which has no text), so every word was empty and every device stayed listed. It now narrows the list as you type: `nphxcoreswi`, `phx AND !dns`, `ptx OR dc`, `NOT phx`. The count line ("2 of 6 shown, 1 picked") shows while a filter is typed, and a device picked stays picked when the filter changes.

### Verified
- The page script's filter block was run in a simulated page (jsdom) with typed input: plain word, AND with `!`, OR, NOT, a picked device kept across filters, and clearing the box. gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles.

### Not verified
- In a real browser, though the simulated page ran the same code and events.

---

## [v211] - 2026-11-17 — an MCP caller may read any path of a device's API; the answer is what is filtered

### Changed
- `device_api_get` no longer refuses a path for the words in it (`vpn`, `ipsec`, `ike`, `crypto`, `users`, `snmp`, `aaa`, `admin`, keys, certificates, your own secret words, a whole configuration). That list was a second guard on top of the filter on every answer, and it kept an assistant from reading what holds no secret (a tunnel's status, the VPN event log, an interface called `vpn`) on every platform. The answer is filtered as before: keys, passwords, communities, pre-shared keys, PEM blocks and the words of Configure ▸ Privacy ▸ Secret words read `(hidden)`, in JSON, text and XML, whatever path the answer came from. The per-platform VPN openings of v209 and v210 are no longer needed and are removed.
- Still refused: what is not a read of that API in the form the device takes (PAN-OS: one `<show>` command, an XPath, or a log search; a log search is one request), a Catalyst's model sources, and the checks inside a driver (Backup Server's accounts and consoles, Junos's configuration RPCs).

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; a test reads the VPN, user and SNMP configuration paths and checks that pre-shared keys, shared secrets, passwords and communities are hidden in JSON and in PAN-OS XML; the tests that expected the word refusals now expect the reads.

### Not verified
- That every secret in every platform's answers is recognised: the filter works by name, so a secret kept under a name nobody listed is shown. Add such names under Configure ▸ Privacy ▸ Secret words. Keep logins on the devices read-only and least-privilege.

---

## [v210] - 2026-11-17 — VPN status readable on every platform that has a status path

### Fixed
- v209 opened a FortiGate's VPN status; the same words (`vpn`, `ipsec`, `ike`, `crypto`) blocked VPN status on the other platforms too. Now readable over MCP, as exact paths only: **Meraki** `organizations/ID/appliance/vpn/statuses` and `/stats`; **Catalyst (IOS-XE)** the `Cisco-IOS-XE-crypto-oper` operational model; **Junos** the RPCs `get-ike-security-associations-information`, `get-ipsec-security-associations-information` and `get-ipsec-statistics-information`; **BIG-IP** `/mgmt/tm/net/ipsec/ike-sa` and `ipsec-sa` (and `/stats`); **PAN-OS** `show vpn ike-sa`, `ipsec-sa` and `flow` (arguments are still checked). The configuration of a tunnel (pre-shared keys: Meraki third-party peers, BIG-IP `ike-peer`, PAN-OS `show vpn gateway`/`tunnel`, `cmdb vpn`, native `crypto`) stays refused.
- Not opened: **Nexus** and **Aruba CX**, where no status path is known to be free of the tunnel's configuration.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; a test per platform checks the status paths are allowed and the configuration, `..` tricks and other commands are not.

### Not verified
- Against real devices. The Meraki, Junos and PAN-OS names are from their documented APIs; the IOS-XE model name and the BIG-IP `ike-sa`/`ipsec-sa` collections are from memory of the product and may differ by release (the device then answers with its own error).

---

## [v209] - 2026-11-17 — FortiGate VPN status and VPN log can be read over MCP

### Fixed
- An assistant could not read a FortiGate's tunnel state or VPN event log: `device_api_get` refused every path with `vpn` or `ipsec` in it, as holding secrets ("path: "vpn" holds secrets…"). That is right for the configuration of a tunnel (`cmdb/vpn.ipsec`, which holds the pre-shared key) but not for the monitor and the log. These are now readable on a FortiGate: `/api/v2/monitor/vpn/ipsec` (and `/select`), `/api/v2/monitor/vpn/ssl` (and `/stats`), `/api/v2/monitor/vpn/ike` (and `/gateway`), and `/api/v2/log/{disk,memory,fortianalyzer,forticloud}/event/vpn` (and `/raw`). Only those exact paths; the answer is still scrubbed of secrets and of public addresses like every other read.
- Still refused, on purpose: the VPN configuration (`cmdb/vpn…`), VPN certificates, SNMP, users, and any other path under `vpn`. Other platforms are unchanged.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; a test checks the allowed paths (also in capitals) and that the configuration, a certificate, `..` paths, tunnel-changing endpoints and other platforms stay refused.

### Not verified
- Against a real FortiGate: the paths are from FortiOS's monitor and log API names, and a release may name one otherwise (then the FortiGate answers with its own error). On PAN-OS the same block on `deviceconfig` and `vpn` is unchanged; say if its tunnel status (`show vpn ipsec-sa`) is needed too.

---

## [v208] - 2026-11-17 — Add device ▸ Devices from inventory has a filter

### Added
- The **Devices** list of *Add device ▸ Devices from inventory* has a filter box below it. Words must all match; `AND` is optional, `OR` makes alternatives (`phx OR sea`), and `!word` or `NOT word` leaves matches out (`phx AND !dns`). It says how many of the devices are shown and how many are picked, a device picked stays picked while the filter changes, and Enter in the box does not submit the form.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; the page script and help parse.

### Not verified
- In a browser: the box was not exercised by clicking, only by the filter code it shares with the other filter boxes.

---

## [v207] - 2026-11-17 — Aviatrix Controller: state and history reads are listed

### Changed
- `device_api_catalog` for an Aviatrix Controller now lists the reads for tunnel and gateway state and for history (`list_bell_notifications`, `get_controller_audit_log`, `get_aviatrix_controller_commandlog`, `list_tunnel_info`, `list_tunnels_latencies`, `get_gateway_stats`, `list_site2cloud_conn`, `list_transit_learned_cidrs` and others), with a note on which to try for "when did this tunnel change state". They were already allowed, but nothing named them, so a caller had to guess action names. A test checks that none of the listed names is refused.

### Not verified
- Against a real controller: the names are from Aviatrix's API reference, and a controller release may name one otherwise. Aviatrix CoPilot is unchanged: its Network Insights API has current state only, no history.

---

## [v206] - 2026-11-17 — Aviatrix Controller and Aviatrix CoPilot

### Added
- New platform **`aviatrixcopilot`** (Aviatrix CoPilot), read only. It uses CoPilot's Network Insights API with the API key (made in CoPilot ▸ Settings ▸ Configuration ▸ General ▸ Features) as the credential's token, on port 443. Facts count the gateways, tunnels and BGP neighbors; Interfaces lists the gateways with their state; Show has `status`, `gateways`, `tunnels`, `bgp`, `metrics [gateway=NAME]` and `gateway NAME`; `device_api_get` reads `/status-api/v1/` and `/metrics-api/v1/gateways`. A wrong key and a CoPilot without the API are told apart in the error.
- A change sent to a CoPilot device is refused with the reason and the way to do it: change the Aviatrix Controller.

### Changed
- The existing **`aviatrix`** platform is shown as **Aviatrix Controller** (GUI, help, README). Its stored platform name is unchanged, so no device or setting needs editing.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; tests for the CoPilot driver against a stub (reads, parsing, wrong key, missing API, refusals) and the every-platform write test.

### Not verified
- Against a real CoPilot. Read/write for CoPilot is **not built**: Aviatrix publishes no CoPilot configuration API (the "API reference" page is the Controller's), so a write would be a guess at an undocumented interface.

---

## [v205] - 2026-11-17 — net_scan takes ports, ranges and subnets

### Added
- `net_scan` (and `--scan`, `POST /api/scan`) can scan **several hosts**: `host` may be a subnet (`10.1.1.0/24`), a range (`10.1.1.10-50` or `10.1.1.10-10.1.1.50`), a host name, or a comma-separated list of these. At most 1024 addresses (a /22) and 20 host names; IPv4 and IPv6 are not mixed; a subnet's own and broadcast addresses are left out.
- `net_scan` takes **`ports`**: numbers and ranges (`22,443`, `1-1024`), at most 1024 ports. Left out, it is the 100 commonest, as before. On the command line: `--scan ADDR|SUBNET|RANGE|LIST --scan-ports 22,443`.
- For several hosts the hosts that answer are found first (nmap's own host discovery) and only those are scanned, so the dead addresses of a subnet are not scanned port by port; a scan of one host still skips the ping. The report says how many addresses were scanned and how many were up, then a short report for each host that is up (OS, MAC, open ports; the first 100 hosts). The scan may run for 2½ minutes plus 3 seconds per host, 15 minutes at most; asked again, it picks up the result.

### Changed
- What reaches nmap is checked first and spelled out: the addresses go to nmap on its standard input and the ports as a list of digits, so nothing a caller types is ever read as an option. A scan of one host with no ports is the same as before.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; tests for the target and port lists (what is accepted and refused), nmap's command line and the report of several hosts.

### Not verified
- Against real nmap on a real subnet: the report of several hosts was tested on sample nmap output, and nmap's real output may differ in a detail.

---

## [v204] - 2026-11-17 — dig works on nodes whose dig refuses "--"

### Fixed
- `net_dig` (and the dig in the GUI) put `--` before the name on dig's command line. Some dig builds answer "Invalid option: --" and show their usage text, so every query on those nodes failed, with or without a server. The name now goes on the command line bare. It cannot be taken for an option: every label of a checked name starts with a letter, a digit or `_`, and the tests check that `-x`, `-f…`, `+short` and `a.-b` are refused.
- The other tools (ping, mtr, curl, nmap) still use `--`; those programs all accept it.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; a test of the command line.

### Not verified
- Against the dig on the affected nodes: I could not see which build they have. If a query still fails there, the error text will now be dig's own.

---

## [v203] - 2026-11-17 — Two cut-off labels

### Fixed
- Configure ▸ Settings ▸ General ▸ Topology: the field is now called **Small square limit** and its hint no longer repeats the range or runs off the box.
- Configure ▸ Devices: the Certificate column was too narrow, so "skip check" lost its last letter under the arrow. It is wider.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; the field hint and help tests. Not looked at in a browser.

---

## [v202] - 2026-11-17 — Version bump

### Changed
- The version number only; the program is the same as v201.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo and the cross-compiles, as for v201.

---

## [v201] - 2026-11-17 — Device changes and captures come from the device's own site too

### Changed
- In a cluster `device_change`, `device_change_raw` and `device_capture` (and the same from the GUI, the CLI and the API) are carried out by the node that checks each device, as the reads have been since v200. The node that got the request makes the change on its own devices, hands the others to the nodes that check them and puts the answers together (one answer per device, `dry_run` and `change` as before). The caller needs the same access as before; the node that makes the change logs it as "user via node".
- Unlike a read, a device whose node does not answer is never done from the node that got the request: it is reported as "did not confirm … may or may not have been made", so a change that may have been made is not made twice. Look at the device before asking again.
- A request that mentions a disabled device is refused as a whole, as before, and a capture on more than 10 devices too.
- `device_troubleshoot_user` is still carried out by the node that got the request.

### Fixed
- On a gateway drawn as small squares (more devices than the threshold), a disabled or paused device was a hollow square that only took the pointer on its 1 px outline, so it was hard to hover. It now takes the pointer over its whole area.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; a test for the split, the put-together answer, no fallback and no second hand-over.

### Not verified
- A real cluster with nodes on separate sites; a change or capture through another node on a real device.

---

## [v200] - 2026-11-17 — Device requests come from the device's own site

### Changed
- In a cluster a device request (`device_facts`, `device_interfaces`, `device_ports`, `device_neighbors`, `device_routes`, `device_firewall`, `device_show`, `device_config` and the other reads, over MCP, the API and the GUI) is carried out by the node that checks the device, whichever node it arrives on. The node that got it hands the devices of another site to that node (`GET /api/devices/query` over the cluster channel) and puts the answers together. The caller's limits go along: an MCP caller stays one (no secrets; the privacy level too) and a read-only account stays read-only; what a key may not use is dropped before anything is sent.
- A node that does not answer is skipped: the node that got the request asks those devices itself. A device that no other node has reported lately is asked from the node that got the request. A request that another node handed over is never handed on.
- A request to a device that no other node checks, and any request outside a cluster, behaves as before.

### Not changed
- `device_change`, `device_change_raw` and `device_capture` (writes) and `device_troubleshoot_user` are still carried out by the node that got the request.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; tests for who checks a device, the hand-over with the caller's limits, no second hand-over, the fallback and a report too old to send the request away.

### Not verified
- A real cluster with the nodes on separate sites. A node on an older version ignores the MCP flags it is sent; netdir hides secrets in the answer again on the node that got the request.

---

## [v199] - 2026-11-16 — AND, OR and ! in every filter box

### Added
- Every filter box in the GUI (Topology, Monitor ▸ Devices, the Configure tables including Tags, the user lists, and the Log) reads `AND`, `OR` and `!`: `phx AND !dns` shows what has phx and not dns. `AND` is optional (`phx !dns` is the same), `OR` takes either side (AND binds first) and `!word`, or `NOT word`, leaves out whatever contains the word. Note: in the Log box a plain word `not` is now an operator, not a word to find. `tag:` words work with `!` on Topology (`!tag:site=dc1`).
- The Log filter already had AND and OR on the server; it now has `!` and `NOT` too.

### Verified
- gofmt, vet, `go test -race ./...`, no-cgo, cross-compiles; the filter parser checked on its own in Node.

### Not verified
- Clicking through each box in a browser: the Topology and Monitor boxes were not driven by a test.

---

## [v198] - 2026-11-17 — The gateway's controller checks its devices

### Changed
- In a cluster a device's health is now checked by the **controller of its gateway**, not by the primary, so the checks stay local to the site. A device on several gateways is checked by only one: the lowest-numbered gateway that holds it and is not paused on every node. For a gateway with both address families the IPv4 controller stands for it (the IPv6 one when the gateway has no IPv4 address). A controller keeps the job for 10 seconds after it loses the election, so a flapping election does not move the checks.
- Every node still shows every device: it reads the other nodes' results over the cluster channel (`GET /api/devices/health`, per node, cached 10 s, older answer used while a new one is fetched) and the newest result of a device wins. The device's tooltip (Topology and Monitor ▸ Devices) says **Checked by** which node did it.
- A result older than a few check intervals reads "not checked" (grey), for instance when the node that checked has gone.
- The primary also checks any device that no other node reports lately, so a gateway whose nodes are all down, or a device whose gateway is paused, is still covered.
- Recheck and "someone is looking" go to the node that checks the device.
- A node outside a cluster checks all its devices, as before.
- Help (Configure ▸ Devices ▸ Checks) and the README say so.

### Fixed
- Stale comment on `devHealth`.

### Verified
- `go test -race ./...`, gofmt, vet, no-cgo and cross-compiles (see below); new tests for the owner gateway, controller detection, the hold, the primary fallback, merging and stale results, and the per-node fetch.

### Not verified
- A real multi-node cluster with controllers on different nodes: only the logic is tested, with a stubbed cluster. After an upgrade the node that checks a device may change; a node that now checks devices will log in to them.

---

## [v197] - 2026-11-16 — A device on no gateway is not used

### Changed
- A device that is on no gateway is treated as disabled: it is never contacted (no health checks, no facts), left out of `list_devices` and the other device tools, and refused by a change, a raw change, a capture or a troubleshoot with "device X is on no gateway: add it to a gateway first". Before, the inventory as a whole was used and a gateway only grouped devices for the drawing and for `gateway:N` limits.
- Monitor ▸ Devices shows such a device with a **no gateway** pill (and the filter finds it by those words); its state reads "on no gateway: never contacted". Putting it on a gateway takes effect within a few seconds, as enabling a device does.
- The inventory itself is not changed: the saved device keeps its own Disabled setting, and Configure ▸ Devices lists every device.
- A configuration with no gateway at all has no device in use.
- Help (Configure ▸ Devices) says so.

### Verified
- Go: a device on a gateway is live, on no gateway is disabled and unattached, on another gateway is live, with no gateways none is; the saved inventory is never changed; the refusal texts. The existing device tests now put their devices on a gateway first (`attachDevices` in the tests).

### Not verified
- A cluster with several nodes after an upgrade: devices that were on no gateway stop being contacted at once (the other nodes' colours follow when they run this version).
- The `/metrics` device series for an unattached device (it reads the same inventory, so it reports it as disabled).

---

## [v196] - 2026-11-16 — Tags are pills; the filter box takes the focus when switching gateways

### Fixed
- Topology: the filter box now takes the focus each time another gateway is picked in the sidebar, not only on the first load (the toolbar is not redrawn when the gateway changes, so the focus was never asked for; now the drawing asks). It does not take the focus from a box being typed in or from an open dialog.

### Changed
- Every Tags box shows its tags as pills instead of space-separated words: the Tags column of Configure ▸ Devices and Add/Edit device (right-click a device on the Topology map). Type a tag, then a space, a comma or Enter to make a pill (a paste of several makes several); the × on a pill, or Backspace in the empty box, takes one off. The tags in use are offered while typing, leaving out those already on the device. A tag typed and not yet made a pill is kept when the dialog's Save is pressed or the box is left.
- Configure ▸ Devices: the table's Tags column takes the room the other columns leave, so the pills fit; the table may use the whole page width.
- Saved as before: the same list of tags per device.

### Verified
- jsdom: with two gateways, picking the other one in the sidebar (and back) leaves the focus in the filter box; pills shown for a device's tags; a suggestion chosen with Down and Enter becomes a pill; several words typed at once become several; Enter; Backspace; the ×; no suggestions for tags already on the device. Chromium (dark): the table and the Edit device dialog.

### Not verified
- Keyboard use with a screen reader (the pills are buttons with "Remove TAG" labels).

---

## [v195] - 2026-11-16 — Configure ▸ Devices ▸ Tags is a table like the others

### Changed
- The Tags tab was a bare list with a cramped tag box. It is now built like the other Devices tables: a filter box with the count, pages (25 to 500 a page), numbered rows, a wide tag box, and a right-click menu on each row: **Rename**, **Copy**, **Show the devices with this tag** (opens the Devices tab with that tag typed into its filter) and **Remove from every device**. Changing the text of a tag still renames it on every device (onto an existing tag it asks, then merges); Enter or leaving the box applies it, Esc puts it back.

### Verified
- jsdom: the listing with counts, the filter ("1–2 of 2 (filtered from 5)"), rename, the right-click menu, Remove, Show the devices (Devices tab with the filter set), and the saved device tags. Chromium (dark): 72 tags over 2 pages, the menu.

### Not verified
- A very long list of tags with the page-size box in a narrow window.

---

## [v194] - 2026-11-16 — The small-squares threshold moves to Configure ▸ Settings ▸ General

### Changed
- The "Squares above [36] devices" box is gone from the Topology page. The setting is now **Configure ▸ Settings ▸ General ▸ Topology ▸ Draw devices as small squares above** (`settings.topology_squares_above`, 1 to 5000, empty = 36). It is a shared setting: the whole cluster uses it, unlike v193's box, which was kept in one browser (that value is no longer read).
- Help (Settings ▸ General and the Topology filter text) describes it.

### Verified
- Go: the setting is validated (0, 1, 36, 5000 accepted; -1 and 5001 refused); help-panel tests. jsdom: the General page shows the field with 36, a change saves `topology_squares_above`; the Topology drawing follows the setting (400 gives all boxes for 320 devices, 300 gives squares, none set gives squares).

### Not verified
- Several nodes in a real cluster copying the setting (it travels as any shared setting does).

---

## [v193] - 2026-11-16 — Tags: the Topology filter finds them, tag boxes suggest the tags in use, and a Tags tab to manage them

### Added
- The Topology filter box has the focus when a gateway's drawing is opened (once for each gateway; later redraws of the toolbar never take the focus from what is being typed).
- Configure ▸ Devices has a fourth tab, **Tags**: every tag in use with the number of devices that carry it; change a tag's text to rename it (onto an existing tag: asks, then merges), **Remove** takes it off every device. It works on the devices table, so it saves like any other change.
- Every Tags box (the Tags column of Configure ▸ Devices, and Add/Edit device on the Topology page) offers the tags already in use while the last word is typed: click one, or Down and Enter/Tab; Esc closes the list. Enter with nothing chosen still submits.

- Topology: **Squares above [36] devices** box beside the filter: how many devices a gateway may have before each is drawn as a small square. Kept in this browser (not in the shared configuration), like the theme; 1 to 5000; 36 is the default.
- A Tags box says so: several tags are separated by spaces.

### Fixed
- Topology, small squares: the full-size card for the square under the pointer is now drawn above it, not over it, so the squares beside and below it can still be reached.

### Changed
- The Topology filter box also searches tags with a plain word (`dc1 core`). The `source=` tag of an imported device is skipped by a plain word (it would match the server's name); `tag:` before a word still searches every tag.
- Help: new topic for the Tags tab; the filter-box text updated.

### Verified
- jsdom: focus on load; plain word matches tags, two words, `source=` skipped, `tag:` finds it; four tabs; the suggestion list, Enter picks, no list when nothing matches; the Tags tab counts, rename, remove and the saved device tags. Go tests (help panels for the new tab).

### Not verified
- The suggestion list's position inside the Add/Edit device dialog in a real browser (it is placed from the box's position inside the dialog); the focus on load in Firefox.

---

## [v192] - 2026-11-16 — Topology: a gateway with more than 36 devices draws them as small squares

### Added
- A gateway with more than 36 devices is drawn with a small square for each device, joined to the gateway by a thin line and coloured by its state, instead of 300 full-size boxes. The full-size square (name, address, platform) shows beside the one the pointer or the keyboard focus is on. Devices that are amber or red are always full size. While the filter box has text, the matches are full size and every other device stays a small square. Clicking, Shift/Ctrl-click, right-click and the tooltip work on a small square as on a box. Drag-to-reorder is off in this drawing (as it already is while a filter is on).
- 36 devices or fewer: the drawing is exactly as before.
- Help (Topology, filter box) describes it.

### Verified
- jsdom: 320 devices give amber/red boxes plus 302 squares with a line each; the hover card shows the hovered device, hides again and is the last thing drawn; the filter gives full-size matches and squares for the rest, and clearing it restores the squares; 36 and 12 devices give all boxes. Chromium screenshots (light and dark) of all four states.

### Not verified
- Behaviour on a real gateway with ~320 devices and a live poll; touch screens (no hover, so a tap selects the device and its tooltip is the only full view).

---

## [v191] - 2026-11-16 — Topology: a node that does not answer cost every poll 2 s; a failed health fetch left 18 s of gray

### Fixed
- The log of v190 (`/api/canvas took 2s … their callers 2s`, on every poll) showed it: `addPeerClients` asked each serving node for its callers with a 2 s limit and, when a node did not answer, kept nothing, so every poll waited the 2 s again (and a page load, with several requests at once, several times over). It now reads the picture `peerCanvasOf` keeps of each node (one background ask at a time, kept 3 s, retried a second after a failure), waits at most 1.5 s for a node it has never heard from and never again for one that did not answer.
- After a failed first fetch of the device health on a node that is not the primary, the retry time was set 8 s into the *future* (the comment says "ask again in a couple of seconds"): the cache counted as fresh and empty for about 18 s, every device gray. It now counts as 8 s old (asked again in 2 s). The same slip is corrected for the nodes' pictures (`peerCanvasOf`).

### Verified
- Tests: a node that does not answer is waited for once and not again, a retry of it starts in the background and holds no request; a failed first health fetch is retried within about 2 s (fails with the old timing); plus the v189/v190 tests. `gofmt -l .`, `go vet ./...`, `go test -race ./...`, no-cgo, 5-arch cross-compile.

### Not verified
- Not run against a real cluster. Why one node does not answer `GET /api/canvas?own=1` within 2 s was not found (it may itself be slow: its own log, with v190 or later, says `web: /api/canvas took …` and which part); it is no longer waited for.

---

## [v190] - 2026-11-16 — Topology after a reload: no waiting on other nodes; a log line for what is slow

### Changed
- `GET /api/canvas` (what Topology polls; blank, with no nodes and the devices gray, until it answers) waited, one after the other, for the primary's device health (up to 5 s), for each node that serves a gateway this node does not (up to 4 s each) and for the nodes' callers (2 s). On a node that is not the primary the sum could be 15 s after a page load. Now a request waits at most 2 s for the device health when this node has none yet, and at most 1.5 s for a node's picture it has none of yet; anything older is used at once while a new one is fetched in the background (`replicaHealth`, `peerCanvasOf`). The next poll, two seconds later, has what the wait missed.
- A node's picture of its gateways is kept for 3 s (it was asked again on every poll).

### Added
- Log lines for the slow part, when the cause is not what the above covers: `web: /api/canvas took 14.2s for "user" (this node …, the nodes that serve its gateways …, their callers …)` for an answer that took over 2 s; `devices: the primary took … to answer for the device health`; `topology: node … took … to give its picture of its gateways`.

### Verified
- Tests: the second asker of the health waits for the fetch in flight and the primary is asked once; a primary that never answers holds a request for no longer than the bound; an older answer is used at once and the refreshed one by the next request.
- `gofmt -l .`, `go vet ./...`, `go test -race ./...`, no-cgo, 5-arch cross-compile.

### Not verified
- Not run against a real cluster, so it is not confirmed that these waits are the 15 s seen on a reload. If it is still slow, the `web: /api/canvas took` line says which part. `liveBGPPeers` (vtysh) and the local part of the canvas are not bounded here; they show in the same line as "this node".

---

## [v189] - 2026-11-16 — Topology no longer starts gray on a node that is not the primary

### Fixed
- On a cluster node that is not the primary, the first look at the devices after a quiet time showed every device gray ("not checked yet") for several seconds. The node has no health of its own and asks the primary for it; the Topology page asks twice at once (the canvas and the devices), and the second request, finding a fetch already under way and nothing cached, was answered with an empty list at once. The second request now waits for that fetch (at most its 5 s timeout plus 1 s), so both get the primary's answer. With an older answer cached it is still used at once. (`devicehealth.go`: `deviceHealth` now hands the replica part to `replicaHealth`.)

### Verified
- `TestReplicaHealthSecondAskerWaitsForTheFetch`: two askers, a slow fetch; the second returns only after it ends, with the same answer, and the primary is asked once. The test fails with the old logic (the second asker returned `map[]` before the fetch ended).
- `gofmt -l .`, `go vet ./...`, `go test -race ./...`, no-cgo, 5-arch cross-compile.

### Not verified
- Not run against a real cluster. A daemon that has just (re)started has no health anywhere until its first round of checks has run (323 devices, 16 at a time, each asked for its facts: some 15 to 20 s); that wait is unchanged, and still shows gray on the primary and on the nodes that ask it.

---

## [v188] - 2026-11-16 — A refused save no longer leaves the Configure page stuck

### Fixed
- Configure pages (Devices and the others made by `makeConfigView`): when the daemon refused a save with "the configuration changed after this page loaded it" (409), the message said the page now showed what is saved, but the page kept its old copy and its old `base`, so every later edit was refused the same way and nothing could be saved until the person reloaded the browser. The page now reads the saved configuration again on that refusal (as the Topology page already did) and then shows the message; the next edit goes out with the fresh base. The edit that was refused is not kept, as the message says: make it again.
- The daemon is unchanged: it still refuses a save made from an older copy.

### Verified
- jsdom with a mock that keeps the base: a save with a stale base is refused once, the page shows "Not saved", and the next edit is sent with the new base and saved (port 9443). The same test fails on v187 (the next edit is sent with the old base again). The v183/v184/v186 jsdom tests still pass.
- `gofmt -l .`, `go vet ./...`, help tests.

### Not verified
- What changed the configuration in the first place was not found: another page or user, an import, or, in a cluster, another node's save (a node that is not the primary compares the page's base with its own copy, which can be a moment behind the primary's). The refusal is correct; only the recovery was wrong. A full `go test -race` run was not repeated (no Go file changed).

---

## [v187] - 2026-11-16 — Edit device kept a wrong port

### Fixed
- Topology ▸ right-click a device ▸ **Edit** opened with the Port box reset to 443 (or the platform's default) whenever the saved port was *any* platform's default, e.g. 8443 on a switch (8443 is the Proxmox Datacenter Manager default). The Port box showed the old value and a Save wrote it over the real one. The port now follows the platform only while it is still the default of the platform the form had before, or empty; a port the device really has is kept when the form opens, and a port typed by hand is still kept when the platform changes. (`webui/app.js`, `deviceForm`.)

### Verified
- jsdom, with a config kept by the mock: a port changed on Configure ▸ Devices is saved (`port: 8443`), shows in the Topology tooltip after Add ▸ Device ▸ from inventory, and the Edit box showed 443 before the fix and 8443 after; changing the platform in the form still fills in the new platform's default (eos → proxmox 8006 → pbs 8007) and keeps a typed port.
- `gofmt -l .` empty; `go vet ./...`; help tests. The v183/v184/v186 jsdom tests still pass.

### Not verified
- The gateway stores only a device's name; its port, address and login always come from the inventory, so adding from inventory copies nothing and the Go side was not changed. A full `go test -race` run was not repeated (no Go file changed since v186).

---

## [v186] - 2026-11-16 — Configure ▸ Devices in three tabs; filter and pages on Logins

### Changed
- Configure ▸ Devices is three tabs, **Devices | Logins | Checks**, like Monitoring (SNMP | Metrics). Every table stays in the page, so the autosave still reads and saves all three together; the login-rename cascade (v183) works with the Devices tab hidden.
- The **Logins** table has the filter box, the page box and the rows-per-page box that Devices has (it was a small table with none). The filter looks at every column except **Password** and **Token**, so typing part of a secret finds nothing.
- `webui/help.js`: the one `config_devices` topic is now `config_devices`, `config_logins` and `config_checks`, and the tab shown picks the topic. The four interval fields were nested inside the Logins entry and never listed; they are now on Checks. `help_test.go` and `help_fields_test.go` follow.

### Verified
- jsdom: three tabs, one shown at a time; Logins with 121 rows: 50 to a page, 3 pages, filter by name and by user name, no match on a password or a token; a rename made on Logins reaches the devices on the hidden Devices tab; the autosave carries devices and logins; Checks has its four boxes. The v183 and v184 tests still pass.
- `gofmt -l .` empty; `go vet ./...`; the help tests.

### Not verified
- Not looked at in a real browser in light and dark; the code adds no styles (the tabs and the bar are the existing classes).

---

## [v185] - 2026-11-16 — Recheck a device now

### Added
- Right-click a device ▸ **Network tools ▸ Recheck** (Topology) or right-click its row ▸ **Recheck** (Monitor ▸ Devices): that device is asked again at once, whatever its state, and a popup says what it answered (`answering`, `refusing` or `unreachable`, and why); *Run again* asks once more, and the Monitor page shows the new state without waiting. It is for after a login or a firewall rule was corrected: a device that *refuses* a request (the amber one) was asked again only every `device_live_facts_min` minutes (5) while someone had Monitor ▸ Devices or Topology open, and every six hours when nobody did, so a corrected login could stay amber for minutes. A device that is unreachable was already asked every round. A disabled device is not contacted (it says `disabled`). Not offered for a device below another Network Director (its state is that director's), nor to an account that can only look.
- `POST /api/devices/recheck {"name"}` answers `{"data":{"name","health":{"status","detail","checked",…}}}` (no facts, no secrets); 400 without a name, 404 for a device that is not there or not in the caller's scope; refused to read-only accounts like every POST. Only the primary of a cluster does the checks, so any other node hands the request to it over the cluster channel (`/api/devices` is already relayable, so the node picker works too) and forgets its few-second copy of the health. `device.Monitor.Recheck` is the check itself (the facts are asked again whatever `FactsAt` says).
- `webui/help.js`: Topology and Monitor ▸ Devices say it.

### Changed
- `webui/app.js`: `toolItems(addr, device)` adds Recheck for a device of this gateway (the Monitor table passes none for a remote row); `recheckPopup`; `VIEWS.devices.refresh()`. Nothing else about the menus or the pages changed.

### Verified
- `gofmt -l .` empty; `go build`; `go vet ./...`; `go test -race -count=1 ./...` (netdir 132 s, netdir/device 10 s); `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` build; `node --check` on `app.js` and `help.js`. New tests: `TestMonitorRecheck` (a wrong password shows `warn`; a round a minute after the login was corrected still says `warn`, as the bug was; Recheck says `ok`; a still-wrong login says `warn` again without the password; a disabled device is not contacted; a missing login says so), `TestHandleDeviceRecheck` (400, 404, a dead port, a disabled device, a caller limited to some devices), `TestRecheckIsAPostRefusedToReadOnly`.
- Live, real daemon with a real PAM login and a stub device that answers 401 until it is "corrected", in headless Chromium: the device shows `refusing`; after the stub is corrected it still does; Topology right-click ▸ Network tools ▸ Recheck and the Monitor row's Recheck both say `answering`, the Topology node turns from amber to green and the Monitor table follows at once; an unreachable device says `the API port does not answer`. Then two daemons in a cluster (a replica joined to the primary by `--cluster-join`): the same Recheck on the **replica** reaches the primary, the replica's page shows `answering` at once, and the primary's own page shows it too. The test user, groups (`netdir`, and the `netdir-ro` the daemon makes) and PAM file were removed afterwards.
- The v183 login-rename and v184 filter/pages jsdom tests still pass.

### Not verified
- The Recheck popup in dark mode, and the Topology submenu in dark mode, were not looked at (the code adds no styles; the popup is the one Ping and Whois use). A read-only account was tested by the unit test only, not live. A node picked in the picker (a request relayed by the picker to a non-primary node, then on to the primary) was not run: the same two relays, each live-tested on its own. No certificate, update or history check was run: none of that code changed.

---

## [v184] - 2026-11-16 — Filter and pages on Monitor ▸ Devices

### Added
- Monitor ▸ Devices: the Devices card has the filter box, the page box and the rows-per-page box of the tables under Configure ▸ Devices (same classes, so the same look in light and dark): the filter keeps the devices that hold every word typed, in any column (name, state as `answering`, `refusing`, `unreachable`, `disabled` or `not checked`, platform, address, the directors between, tags); the count reads `1–50 of 130` (`(filtered from N)` while a filter is on); « ‹ page › » and 25, 50 (the start), 100, 250 or 500 rows to a page; the pager hides when there is one page, and the box hides when the inventory is empty. A filter with no match says so in the card.
- The page polls the devices every few seconds. The bar is built once and a poll redraws only the table, so what is typed, the page, the page size and the focus stay; a page past the end after the list shrinks is pulled back to the last. The tiles still count every device, not the filtered ones.
- `webui/help.js` (Monitor ▸ Devices) says it.

### Changed
- `webui/app.js` only (`VIEWS.devices`); the table's columns, the state pills, the right-click menu and the tooltips are as they were. No change to the daemon, the API or the config.

### Verified
- `gofmt -l .` empty; `go build`; `go vet ./...`; `go test -race -count=1 ./...` (netdir 130 s, netdir/device 11 s); `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` build. `node --check` on `webui/app.js` and `webui/help.js`.
- A throwaway jsdom test (scratch directory, not in the repo) loads the real `app.js` against a mocked API with 131 devices: the first page, next, last, the page box, 25, 50 and 100 rows to a page, the filter by name, platform, state, tag and address, several words, no match, clearing it, and a poll while a filter is typed and the focus is in the box (text, page and focus stay; the tiles count all); the list shrinking while on the last page; an empty inventory. The same test against the v183 `app.js` fails at once (no bar). The v183 login-rename test still passes.
- Looked at in headless Chromium (light and dark), unfiltered and filtered, and the "?" panel of the page in both.

### Not verified
- Not run against a live daemon with real devices: the page was served from the real `webui/` files with a mocked API. The real PAM login and the cluster checks were not run: no auth, session, cluster or Go code changed.

---

## [v183] - 2026-11-16 — Renaming a login renames it on every device that uses it

### Changed
- Configure ▸ Devices: a device holds its login by name, so renaming a login in the Logins table left every device that used it pointing at a name that no longer existed, and the save was refused (`device X: credential "old" is not in the credentials list`) until each device's Login was changed by hand. Now, when a login's name is entered, every row of the Devices table whose Login is the old name takes the new one at once, and the form's autosave then carries both in the same save. A rename follows from the name the login had when the page was drawn (or last renamed), so renaming it twice in one visit works, and a swap of two names is done in one step. A name another login already has is not followed (the daemon still refuses that save as "listed twice"); fixing it to a free name then follows from the real old name. Editing a password, user name or token moves nothing.
- `webui/app.js` only: `rowTable` gains `track` (the Logins table sets it), `renames()`, `commit()` and `retarget()`, and `fieldset` gives its row tables back through `table(key)`. The daemon, the config format (`credential` is still the login's name) and the API are unchanged, so a hand-edited config or an API client still has to rename a login's references itself. `webui/help.js` (Configure ▸ Devices) says it.

### Verified
- `gofmt -l .` empty; `go build`; `go vet ./...`; `go test -race -count=1 ./...` (netdir 134 s, netdir/device 11 s) all pass; `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...` pass; `linux/amd64`, `arm64`, `arm`, `386` and `riscv64` build. `node --check` passes on `webui/app.js` and `webui/help.js`.
- A throwaway jsdom test (scratch directory, not in the repo) loads the real `app.js` and `help.js` against a mocked API, opens Configure ▸ Devices and edits the Logins table: a rename updates the Devices table's Login column and the autosave PUT carries the new name on every device that used it with the secrets untouched; a second rename continues from the first; a rename onto an existing name moves nothing and fixing it follows; a password edit moves nothing. The same test against the v182 `app.js` fails 7 of its 13 checks.

### Not verified
- Not clicked through in a real browser (Chromium, light and dark): nothing about the layout changed, and only the jsdom test above drove the page.
- The real PAM login and the multi-daemon cluster checks were not run: no auth, session, cluster or Go code changed.
- Not covered on purpose: a rename made outside the web GUI (a hand-edited `netdir.conf`, `PUT /api/config`) is not followed.

---

## [v182] - 2026-11-16 — Make the scan command findable

### Fixed
- An MCP client asked to "scan the tv library" on a multi-media[encoder] started a real encode with `start_job` (stopped again, queue left holding the scan's files): `show scan` (v181) was not named in the `device_show` tool description, which lists the show names for no mediaencoder, and the `device_change_raw` description listed `start_job` without saying what it does.
- `device_show` now names the mediaencoder reads and says `show scan target=movies|tv|/dir` is the scan-only command and to use it instead of `start_job`. `device_change_raw` says `start_job` starts a real encode job and points to `show scan`. The platform help says the same.

### Verified
- Against the live encoders (both v25): `show scan target=tv` on nvenc1-mme checked 4494 files and reported 114.8 GB to encode, and started nothing.
- `VERSION` is `182`. Checks as for v181.

## [v181] - 2026-11-16 — Ask multi-media[encoder] what it would encode

### Added
- **`show scan target=movies|tv|/absolute/dir`** for the `mediaencoder` platform (`device/mediaencoder.go`, needs multi-mediaencoder v25): calls the encoder's read-only `scan_library` tool and returns what a job on that target would encode (counts, bytes to encode, the file lists, which already-optimal files a real job would rename). Nothing is encoded, renamed or changed on the encoder, no job is started, and it is a read, so it works with `NETDIR_DEVICE_GUARDS=1` on. It can take a while on a large library.
- `target` is checked before anything is sent: `movies`, `tv` or an absolute path (spaces allowed, no control characters, 1024 bytes at most); a missing or relative target is refused without a call. `scan_library` is not accepted as a `CALL` action.
- README and the platform help say so. `TestMediaEncoderScan` in `device/mediaencoder_test.go`.
- `VERSION` is `181`.

## [v180] - 2026-11-16 — Delete the multi-media[encoder] quarantine from netdir

### Added
- **`purge_quarantine` for the `mediaencoder` platform** (`device/mediaencoder.go`, needs multi-mediaencoder v24): `device_change_raw` with method `CALL`, path `purge_quarantine`. With no body it deletes every file in the encoder's quarantine (the originals kept after an encode); `{"older_than_days": N}` deletes only older ones. The encoder has a real dry run for this tool, so a dry run here (or `"dry_run": true` in the body) asks it what would be deleted, and `Before` holds its list; nothing is deleted. The answer holds the count and the space freed.
- `show quarantine` and the API route `/api/quarantine` (the quarantine's size per folder, the oldest age and what the automatic purge would delete next).
- Arguments are checked before anything is sent: `older_than_days` a number from 0 to 3650, `dry_run` a boolean, no other key.
- With `NETDIR_DEVICE_GUARDS=1` only a dry run of `purge_quarantine` is accepted (it joins `clear_log`, `clear_history` and `clean_temp_files`).
- README, the platform help and the `device_change_raw` description say so. Tests in `device/mediaencoder_test.go`: show and API, the dry run (the tool is called with `dry_run: true`), delete all, `older_than_days` passed on, a body `dry_run`, every bad argument refused without a call, guards on and off.

### Changed
- `VERSION` is `180`.

### Verified
- `gofmt -l .` clean, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, the cgo-off `go vet`/`go test`, `sh tools/leaktest.sh`, `node --check webui/help.js`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.
- **Against a real multi-mediaencoder v24 daemon** with quarantine files of two ages: a throwaway program using the driver ran `show quarantine`, a dry run (listed both files, deleted none) and `CALL purge_quarantine` with no body: both files were deleted (1.2 MB), the marker file stayed and the encoder's log read "requested by mcp". The daemon and its files were removed afterwards.

### Not verified
- Only against the encoder's quarantine on a local file system: not on NFS or SMB, and not with `quarantine_dir` set to another disk.
- The wording of the GUI help was syntax-checked, not looked at in Chromium.


## [v179] - 2026-11-16 — A driver for multi-media[encoder] (`mediaencoder`)

### Added
- **Platform `mediaencoder`** (`device/mediaencoder.go`): the multi-media[encoder] NVENC HEVC re-encoding daemon (multi-mediaencoder v23 and later), reached through its own MCP endpoint (`POST /mcp` on its web port, default 8765) with the encoder's MCP token as the credential's token. Standard library only. Like `dnsdir`, `ntpdir` and `netdir` it only calls the other end's tools; it needs no change to the encoder.
- **Reads.** Facts: release (from `initialize`, which must say it is a `multi-mediaencoder`), the cluster name and node count when the encoder's cluster is on, the GPU model. Resources: CPU, load, memory, swap and the GPU's load, NVENC/NVDEC, memory, temperature, power and fan (the newest `get_metrics` sample). Config: `get_config`. Show: `show status|live-session|queue|log|history|history-log|metrics|cluster|cluster-check|schedules|config` with `lines=` (1 to 2000) and `id=` checked before anything is sent. API: the encoder's own routes that have a read tool (`/api/status`, `/api/live-session`, `/api/queue`, `/api/log?n=`, `/api/sessions`, `/api/sessions/ID/lines`, `/api/sys`, `/api/gpu`, `/api/cluster`, `/api/cluster/check`, `/api/schedules`, `/api/config`), plus a catalog. Interfaces and Neighbors answer `ErrUnsupported` (not a network device).
- **Changes** (`RawChange`, so `device_change_raw`, rw): method `SET` (a JSON object of settings, through `set_config`) and method `CALL` with the action as the path: `start_job`, `stop_job`, `stop_cluster_jobs`, `drain_node`, `create_schedule`, `update_schedule`, `toggle_schedule`, `run_schedule`, `delete_schedule`, `clear_queue`, `clear_log`, `clear_history`, `clean_temp_files`. The encoder has no dry run, so a dry run checks the request here, reads how things stand (the settings it would replace, the status, the schedules or the cluster) and sends nothing that changes. `Before` holds what was replaced; nothing is put back. With `NETDIR_DEVICE_GUARDS=1`: `clear_log`, `clear_history`, `clean_temp_files` and setting `allowed_groups`, `session_hours` or `port` are refused.
- `cluster_secret`, `plex_token` and `mcp_token` are never set from here (refused before anything is sent) and the encoder leaves them out of its answers; there is no tool for its certificate, Plex sign-in or tokens. The token is in no error text.
- Registered everywhere a platform is: default port 8765 (`device.go`, the GUI's `PORT_DEF`), the GUI's platform names, the add-device and platform help (`webui/help.js`), the CLI help (`main.go`), the `device_change_raw` description (`devraw.go`), the README (drivers table, platform list, a `mediaencoder` section), `netdir.conf.example`, `tools/devprobe/lab.json.example` (with an `enckey` login), `CLAUDE.md`, the no-restart note in `rawreboot.go`, and the "every platform is writable" and default-port tests.
- Tests: `device/mediaencoder_test.go` against a TLS stub of the encoder's endpoint: registration and port, facts, resources arithmetic (MiB to bytes, sensors, three memory pools), every show name and the arguments refused without a call, the API routes and the paths refused, wrong token (401, token not in the error), MCP switched off (404 gets a plain message), another MCP server refused, SET and CALL (dry runs send nothing that changes; secrets, unknown actions, a bad id, lines and other methods refused before a call; the encoder's own refusal comes back as the error; guards on and off).

### Changed
- `VERSION` is `179`.

### Verified
- `gofmt -l .` clean, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (main package and `./device`), after `apt-get install libpam0g-dev`. `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...` pass (stub path). `sh tools/leaktest.sh` passes (the new platform needed no change there: it has the same set of optional interfaces as `nios` and `technitium`). `node --check` on `webui/app.js` and `webui/help.js`.
- **Against a real multi-mediaencoder v23 daemon** (built from its source and started with a scratch directory and a generated token): `go run ./tools/devprobe` with `-op facts` (release v23), `config` (its three secrets absent), `show status|metrics|schedules|log lines=3|cluster`, `interfaces` (unsupported), and a wrong token (401). A throwaway Go program using the driver ran `SET` (dry run and applied: `config.json` held the new values), a `SET` the encoder refused (HTTP 400 and its text came back as the error), `CALL create_schedule`, `CALL start_job` (the encoder's log shows the scan "by mcp") and a `start_job` on a missing directory (400 with the encoder's message), plus `/api/schedules` through the API reader. The daemon, its files and the program were removed afterwards.
- Cross-compiled `linux/amd64`, `arm64`, `arm`, `386` and `riscv64`.

### Not verified
- **Resources on an unwatched encoder: it is empty by the encoder's design.** Version 23 of the encoder samples its host and GPU only while a browser has its page open, so `get_metrics` has no samples otherwise. The driver says so in `Details.Unavailable` instead of guessing. The numbers (CPU, memory, GPU) were verified only against the stub, never against a sampled encoder or a real NVIDIA GPU. Making the encoder sample when an MCP client asks is a change in the encoder, not here.
- Facts has no host name unless the encoder's cluster is on (its MCP server has no tool that returns one) and no uptime or serial.
- Not run: the cluster, web GUI, install, federation or live multi-node checks of this file's process: nothing in those code paths changed. The new GUI text was syntax-checked, not looked at in Chromium; the only GUI changes are two entries in lookup tables (a port and a platform name).
- The driver reaches the encoder only over HTTPS (the encoder's default); an encoder started with `-no-tls` cannot be reached. Not tested through a reverse proxy or with a CA-signed certificate (`ca_pem`).


## [v178] - 2026-11-15 — Tested on real equipment; the documentation says what v172 did

### Verified
- The maintainer ran the features of v170 to v177 on real equipment and they worked: clearing port counters, saving the configuration, the typed port changes on Junos, NX-OS, FortiOS and BIG-IP, VM and container create, delete and resize, `rw` without the refusal lists, the `linux` and `windows` drivers, and the Proxmox and vCenter imports. The "Not verified" notes of those releases below are what was true when each was cut. (Which models and versions were used was not recorded here.)

### Changed
- **Documentation**: every place that said a change is refused, never done or never touched (README, the help, the vCenter API catalog) now says it is refused only with `NETDIR_DEVICE_GUARDS=1`, the switch v172 added; the help opens its platform list with one note saying so. The README's description of what a raw change still checks is rewritten to the plain-path and well-formed-body checks that remain. A port that holds the gateway's address is shut down when the lists are off, as v172 made it; the README no longer says it is never shut down.
- The README and the help no longer say the `linux` and `windows` drivers were not run on real hosts.
- No code changed except the text of one API catalog answer (vCenter). A check of every refusal site in the drivers found each one inside a guard that `NETDIR_DEVICE_GUARDS` switches off; the only ones that stay on are the well-formedness checks (method, path shape, JSON where JSON is wanted).

## [v177] - 2026-11-15 — Import the virtual machines of a vCenter

### Added
- **Import ▸ Devices / Preview on a `vcenter` device** (`device/import.go`): each powered-on VM (`/vcenter/vm?power_states=POWERED_ON`) becomes a `linux` or `windows` device, disabled, no login, tagged `source=vcenter` and `vm=ID`. System: the guest family of `/vcenter/vm/ID/guest/identity` (VMware Tools), else the guest OS of `/vcenter/vm/ID`. Address: a usable IPv4 address from the Tools (the identity, then `guest/networking/interfaces`), else the Tools' host name or the VM's name (tag `address=name`). Off or suspended machines, other systems and unknown ones are skipped with the reason.

### Not verified
- Not run against a real vCenter: the test feeds canned answers in the shapes of the vSphere Automation API. A VM name with spaces becomes a name with dashes. Two VMs of the same name in different folders import once (the second is skipped as the same name). An account without read access to a machine's guest data gets the guest-OS judgement and the VM's name as its address.

## [v176] - 2026-11-15 — Proxmox import: only guests that are powered on

### Changed
- **Import ▸ Devices / Preview on a `proxmox` device** takes only running VMs and containers; a stopped or paused one is listed as skipped ("is not running") and no more of its API is read. Its address therefore always comes from what the running guest reports (guest agent, container interfaces), else its static configuration, else its name.

## [v175] - 2026-11-15 — Windows hosts over OpenSSH (`windows`)

### Added
- **`windows` platform** (`device/windows.go`): facts, interfaces and ports with counters, routes, resources, configuration (ipconfig, routes, DNS, firewall), `show` commands from a fixed list (`ip`, `links`, `routes`, `neighbors`, `ports`, `services`, `service NAME`, `processes`, `eventlog`, `log`, `disk`, `memory`, `cpu`, `version`, `firewall`, `dns`, `time`, `users`, `updates`, `shares`) with the same filters as Linux, typed shutdown and no shutdown (`Disable-NetAdapter`, `Enable-NetAdapter`; `ethernet2` finds *Ethernet 2*), and raw lines of PowerShell (`$ErrorActionPreference = 'Stop'`).
- Transport shared with `linux`: the script is base64-encoded into one line of PowerShell fed to `powershell -Command -` on standard input (`winInvocation`), so there is no cmd.exe quoting and no command-line length limit; `sshExec` now asks `remoteInvocation` for the command and the standard input. The password is in neither.
- **Proxmox import**: a VM whose `ostype` is Windows (`win*`, `w2k*`, `wxp`, `wvista`) is imported as a `windows` device (it was skipped).
- Port grammar accepts `ethernet` and `wi-fi` as written. The default port is 22; the web UI, help and README list the platform.
- **Devices table**: a field whose text is longer than its box shows the whole text as a tooltip. Configure ▸ Devices (and every other row table): checked when the pointer arrives, the box is focused or its text changes; a box that is wide enough has none; a password or token is never put in a tooltip. Monitor ▸ Devices: a cell cut with an ellipsis (the name, say) shows its text; the State cell keeps its own tooltip.
- Tests: `windows_test.go` with a fake runner and a stand-in `ssh` that records its arguments and standard input.

### Not verified
- Nothing was run against a real Windows host. The property names of `Get-NetAdapter` (`Speed`, `MtuSize`, `FullDuplex`, `ifIndex`) and `Get-NetAdapterStatistics` are those of Windows 10 / Server 2016 and later; an older release may lack some, and the answer shows zero for them.
- PowerShell 7 or Windows PowerShell 5.1: only `powershell` (5.1) is started. A host with only `pwsh` would need the command changed.
- A non-administrator can read most things and change nothing; the refusal is Windows's.
- `Get-WinEvent -LogName Security` needs an administrator.

## [v174] - 2026-11-15 — Import the VMs and containers of a Proxmox VE host

### Added
- **Import ▸ Devices / Preview on a `proxmox` device** (`device/import.go`, `ImportSources`): each VM and container of the cluster (`/cluster/resources?type=vm`) becomes a `linux` device, disabled, no login, tagged `source=proxmox`, `node=`, `vmid=` and `type=qemu|lxc`. Address, in order: the QEMU guest agent (`network-get-interfaces`) or the container's `/interfaces` while it runs; a static address in the configuration (`ipconfigN`, `netN` `ip=`); the guest's name (tag `address=name`). Loopback, link-local, Docker, bridge and veth addresses are never taken.
- Skipped with a reason: templates, VMs whose `ostype` is not `l24` or `l26`, unmanaged containers, entries that are not guests, guests whose configuration could not be read, and guests already in the inventory.
- Guest reads run 8 at a time; a skipped row now names the guest.

### Not verified
- Not run against a real Proxmox VE: the test feeds canned answers. The guest agent's and the container interface list's answer shapes are those in Proxmox's API documentation. A token without VM.Audit may see no guests, or no configurations.
- A guest with several network cards gets the first usable IPv4 address, which may not be the one the gateway reaches.

## [v173] - 2026-11-15 — Linux hosts over SSH (`linux`)

### Added
- **`linux` platform** (`device/linux.go`): facts, interfaces, ports with counters, routes, resources, LLDP neighbors (`lldpctl -f json`), a configuration of the network files and tables, and `show` commands from a fixed list (`ip`, `links`, `routes`, `neighbors`, `ports`, `services`, `service NAME`, `logs`, `log UNIT`, `disk`, `memory`, `cpu`, `processes`, `version`, `firewall`, `dns`, `time`, `users`) with `include`, `exclude`, `begin`, `head`, `last` and `count` filters done here.
- **Login**: user name with a password (through `SSH_ASKPASS`; also to `sudo -S` for privileged commands) or a PEM private key as the token; neither means the daemon's own keys and `sudo -n`. Host key learned on first use (`accept-new`) or not checked with `insecure`. Runs the system `ssh` (`NETDIR_SSH` overrides the path), so the project stays stdlib-only. Option `sudo=no`; root never uses sudo. The script travels base64-encoded, so no quoting of the remote shell matters; the host name and user name are checked so neither can be taken for an ssh option.
- **Typed changes**: description (interface alias), shutdown, no shutdown (`ip link set`). Port grammar: `eth0`, `eth0.100`, `ens3`, `enp1s0`, `br0`, `bond0`, `wlan0`, `docker0`, `veth…`, `lo` are taken as written (eth0 is read back from the Cisco spelling when the host has it). Clearing counters is refused; `save` says there is nothing to save.
- **Raw changes**: `lines` of shell as root through sudo, one script with `set -e`; the answer carries what the lines printed. With the lists on (`NETDIR_DEVICE_GUARDS=1`) power, disk, user and firewall-flush commands are refused; by default they are not.
- Web UI, help and the device documentation list the platform; the default port is 22.
- Tests with a fake runner (`linux_test.go`) and a stand-in `ssh` that records its arguments, its standard input and its environment: the password is never in the arguments, a key file is mode 600 and removed afterwards.

### Not verified
- Nothing was run against a real Linux host or a real `ssh`: the `ip -j`, `lldpctl -f json`, `free`, `df` and `journalctl` output shapes are those of current distributions, and an old iproute2 (before 4.13) has no `ip -j`.
- `lldpctl` JSON differs between lldpd releases; two shapes are handled (the chassis keyed by the neighbor's name, or holding it).
- A host that asks for a password for sudo on a terminal (`requiretty`) cannot be used with `sudo -S` here.
- Raw lines have no rollback and typed changes are not persisted across a reboot.

## [v172] - 2026-11-15 — An `rw` key means `rw`: the refusal lists are off

### Changed
- **No lists of refusals for `rw` callers.** Every guard that refused a write by what it touched is behind `guardsOn` (default off): the per-platform path guards of `restRaw`, the CLI line denies (EOS, NX-OS), Proxmox, PDM and Proxmox-MX body checks (`purge`, `archive`, ...), BIG-IP body check, Technitium path denies, Aviatrix key, action and gateway-delete denies, Junos `delete` and line/RPC denies, PAN-OS `mgt-config`, Entra allowed-resource and password checks, vCenter/PDM/Proxmox delete refusals via their guards, and the refusal to shut the management port. Users, tokens, keys, certificates, files, deleting infrastructure and cutting your own management access are now sent if the device allows them.
- Still checked: the method, a path that starts with a single `/` and holds no host, space, control character, `#` or backslash, and bodies that must be JSON. Still done: the read before a change, put-back of a failed PUT or PATCH, Junos and EOS confirmed commits, the NX-OS checkpoint. `ro` keys and read-side masking are unchanged.
- `NETDIR_DEVICE_GUARDS=1` in the daemon's environment turns the lists back on; `device.SetGuards` does the same in tests (the refusal tests run with it on).

### Added
- `guardsoff_test.go`: pass-through with the lists off, and the path sanity check.

### Not verified
- Nothing in this release was run against a real device. A change that locks you out is not undone by netdir where the platform has no rollback (POST, DELETE, most CLI platforms).
- Every guard function is reached only through `restSpec` (now gated), so the vCenter, PDM and Proxmox structural delete refusals are off too. `nsone.go` still calls its own guard to choose a path and was not changed.

## [v171] - 2026-11-15 — Typed port changes on more platforms; `save`; rw callers create, delete and resize VMs and containers

### Added
- **`save` on `device_change`** (MCP `save`, API `"save": true`, CLI `--device-save`). After a change that was made, the configuration is saved so it survives a reboot: IOS-XE (`cisco-ia:save-config`), NX-OS (`copy running-config startup-config`), EOS (`write memory`), Aruba CX (a PUT of `/fullconfigs/startup-config` from the running one) and BIG-IP (`save sys config`). Junos (commits), FortiOS and Meraki keep a change on their own, and the result says so in `note`. A plan (`dry_run`) never saves, a change that was refused or put back is not saved, a save that fails leaves the change in the running configuration and says so in `note`, and `clear_counters` has nothing to save. New `device.ConfigSaver` interface; `ChangeResult` has `saved` and `note`.
- **Typed description, shutdown and no shutdown on Junos, NX-OS, FortiOS and F5 BIG-IP** (`device/ifacewrite.go`). Each reads what a port holds from the driver's own `Interfaces`, builds the platform's request from the validated fields and sends it through that platform's `RawChange`, so its guards, checkpoint or confirmed commit, and rollback apply; `runChange` then reads back and writes the old values when something differs. Junos: set-format lines (`set interfaces ge-0/0/1 disable`, `… description "text"`), one request; NX-OS: `interface X`, `shutdown`, `description …` as one `cli_conf` request after a checkpoint; FortiOS: `PUT /api/v2/cmdb/system/interface/NAME` with `{"status": "down"|"up"}` or `{"description": …}`; BIG-IP: `PATCH /mgmt/tm/net/interface/NAME` with `{"disabled": true}` or `{"enabled": true}` or a description (only the physical interfaces are ports, not the self IPs). A port holding the address the gateway reaches the device on is never shut down. **PAN-OS** has no typed shut or description (a link-state or description change is a configuration change and a commit that also commits other people's pending changes): counters only; `device_change_raw` for the rest. Aruba CX and Meraki were already typed; Junos and PAN-OS also take `clear_counters` (v170).
- **Port names of those platforms** in the grammar: Junos `ge-`, `xe-`, `et-`, `ae`, `irb` (`ge-0/0/1-3`), FortiOS `port1`, `wan1`, `lan1` and bare `dmz`, `lan`, `wan`, `internal`, `ha`, `fortilink`, `modem`, BIG-IP `1.1` and `mgmt`. Anything else is still refused; every name is then matched with the device's own list.

### Changed
- **VM platforms: `rw` means creating, deleting and resizing VMs and containers.** Proxmox VE and Proxmox Datacenter Manager: `DELETE /nodes/N/qemu/ID` and `…/lxc/ID` (PDM: `DELETE /pve/remotes/R/qemu/ID`) are no longer refused, and `purge` and `destroy-unreferenced-disks` are accepted in the body of that one request (anywhere else they are still refused, with `remove-vanished` and `destroy-data`); creating (`POST /nodes/N/qemu|lxc`), `PUT …/config` (cores, memory, disks) and `PUT …/resize` were already open. vCenter: `DELETE /vcenter/vm/ID` is no longer refused; creating, cloning and changing CPU, memory and disks were already open. **Still refused:** restoring a backup (a body with `archive`), rolling back a snapshot, migrating a guest to another cluster (PDM), removing a remote, deleting a storage or its volumes, removing a disk from a machine (`unlink` on Proxmox, a disk DELETE on vCenter), deleting a vCenter host, cluster, datacenter, datastore, folder, resource pool or network, and everything else on those lists. README and help text say so.
- `device_change` tool text and the "no typed changer" error name the platforms; the README's "Changing devices" paragraph too.
- The test that used NX-OS as "a platform with no typed writer" uses Infoblox NIOS.

### Verified
- gofmt, go vet, go test -race -count=1 ./..., the leak test. New tests: IOS-XE, EOS and AOS-CX savers against their stubs; `save` through the MCP tool (a plan does not save, a change does once, `clear_counters` says nothing to save); Junos, NX-OS, FortiOS and BIG-IP changes through a fake device (the exact lines and bodies, plan, shutdown, already-as-asked, no shutdown, a description with quotes and a backslash, a missing port cancels, a refusal is passed up) and that a line break, a `;` or a path in a port name is refused; the port grammar for the new names; Proxmox create, resize and delete (and that `purge` is refused anywhere else), PDM guest delete, vCenter create, clone, delete, CPU, memory and disk (and that host, datastore and disk deletes are still refused).

### Not verified
- **Nothing was run against real gear or real hypervisors.** The Junos, NX-OS, FortiOS and BIG-IP changes were tested through a fake of their `RawChange`, not a stub of their APIs; the field names (`status`, `disabled`/`enabled`, Junos `disable`) are from the vendors' documentation. Whether Junos and NX-OS read back the admin state the same way after the change as before was not seen. The Aruba CX save (`PUT /fullconfigs/startup-config?from=…running-config`) is from memory of the REST documentation. Proxmox takes `purge` and `destroy-unreferenced-disks` as parameters of the DELETE; whether a DELETE body is read as such by Proxmox was not tried.
- v170's clear-counters notes stand: untried on real devices.

## [v170] - 2026-11-15 — Clear interface counters (`clear_counters`) in `device_change`

### Added
- **A fifth typed change, `clear_counters`**, for `device_change` / `--device-change` / `POST /api/devices/change`. In English: `clear all port counters`, `clear counters on gi1/0/1-4`, `reset all interface statistics` (clear, reset or zero; counters, statistics or stats; for, on, of, from or in). Typed: `action: clear_counters` with `ports` (named, or empty or `all` for every port). The plan (`dry_run`) lists the ports a clear would reach.
- **Platforms that do it:**
  - Cisco IOS-XE: `POST /restconf/operations/Cisco-IOS-XE-rpc:clear` with `{"Cisco-IOS-XE-rpc:input": {"count": "<interface>"}}` (an empty `count` is every port). The RPC's `interface` leaf is `clear interface`, which resets the port, and is never sent. The RPC and its leaf are from Cisco's `Cisco-IOS-XE-rpc` YANG (release 17.18.1 copy); the switch's own copy of that source cannot be read over MCP.
  - Arista EOS: `clear counters [Interface]` over eAPI, sent as plain exec commands (no configuration session).
  - Juniper Junos: the RPC `<clear-interfaces-statistics><all/></clear-interfaces-statistics>` over the REST API. All ports only: Junos port names (`ge-0/0/0`) are not in the typed port grammar.
  - Palo Alto PAN-OS: the operational command `<clear><counter><interface/></counter></clear>` over the XML API. All ports only: the command takes no interface.
- **Platforms that cannot, and say so:** Aruba CX and Meraki (no such call found in their REST APIs), FortiOS (its monitor API clears counters of policies, VIPs and ACLs, not of interfaces) and NX-OS (the driver only sends `cli_show` requests, never a command that changes anything; NX-API REST has a clear action on `sys/action` but its payload was not verified). Each answers "this platform's API has no way to clear interface counters". `device_change_raw` is still open for them where the platform has a way.
- Counters are not configuration, so a clear is planned from the device's own port list (a port the device lacks cancels the change), sent, and **not read back and not put back**; the result says `applied` when the device accepted the request. A port holding the gateway's management address may be cleared (only a shutdown is refused there).
- `device.AllPorts`, `device.AllPortsChange()`, `Change.All()`, the `counterClearer` interface and `runClear` in `device/change.go`; `device/junos_write.go` and `device/panos_write.go` (Junos and PAN-OS had only raw changes before; their typed `Change` accepts nothing but this action).

### Changed
- `eosCfgRE` also accepts `clear counters` with an optional interface name, nothing else new.
- README: the `device_change` rows and the "Changing devices" paragraph.

### Verified
- gofmt, go vet, go test -race -count=1 ./... pass. New tests: the English grammar and Validate for the new action (and that "clear the description" is not shadowed), `runClear` with a fake device (named, missing port, dry run, refusal, other action), the IOS-XE stub (the `count` leaf, an empty one for all, a missing port cancels, the management port may be cleared) and the EOS stub (the exact exec lines, with no session).

### Not verified
- **Nothing was run against real gear.** The IOS-XE RPC is taken from the YANG, not seen answering on a switch (whether `clear counters` with an empty `count` asks a confirmation the RPC does not answer is unknown). The EOS, Junos and PAN-OS commands are the documented CLI commands in their API forms; Junos and PAN-OS have no stub test of their own. Run `--device-change "clear counters on …" --dry-run` first, then one port.
- The running netdir has to be updated to this version before the MCP `device_change` tool offers `clear_counters`.

## [v169] - 2026-11-15 — Ask removed from a device's right-click menu

### Removed
- **Ask ▸** (Facts, Interfaces, Ports, Neighbors, Routes, Firewall, Configuration, Show command, Look up user/computer/group) from a device's right-click menu on Topology. The menu is now: Network tools ▸, (Import / Troubleshoot / Sign in for the platforms that have them), Edit, Copy, Paste, Pause ▸, Delete. The code behind it is gone too. Asking a device is still possible from an assistant over MCP (`device_facts`, `device_show` and the rest) and the API; the web GUI no longer has a way to do it.

### Verified
- gofmt, go vet, go test -race pass; the device menu in headless Chromium.

### Not verified
- Nothing tested against real devices.

## [v168] - 2026-11-15 — Device right-click menu; Pause a device on this node; copy and paste anycast addresses

### Changed
- **A device's right-click menu on Topology** is now: Ask ▸, Network tools ▸, (Import / Troubleshoot / Sign in for the platforms that have them), then Edit, Copy, Paste, Pause ▸ (This node / All nodes), and Delete. **Ask ▸** is kept because it is the only place left in the GUI to ask a device (Monitor ▸ Devices no longer has the form). **Delete** takes the device off this gateway, the same as the Delete key; it stays in the inventory. To remove it from the inventory, pick it and choose **Delete devices**, or use Configure ▸ Devices. **Copy** / **Paste** are the old Copy device / Paste device; Paste puts the copied device(s) on this gateway.
- **Pause ▸ All nodes** is what Disable was (the inventory's switch: no node contacts the device). **Pause ▸ This node** is new: only this node leaves the device out (the saved list `paused_devices_here`, local to the node, not replicated); the drawing shows it as paused and the tooltip says "Paused on this node". A name no longer in the inventory is dropped from the list when the configuration is saved. History shows it as "paused on this node: NAME".
- CLI: `--canvas-pause|--canvas-resume device --device NAME --scope node|all` (default all, as before).

### Added
- **Copy and paste anycast addresses**, as in dnsdir and ntpdir: right-click an anycast address ▸ Copy ▸ Anycast address or All anycast addresses (also put on the system clipboard as text); right-click another gateway ▸ Paste ▸ Anycast address or All anycast addresses. An address the gateway already has, or that is any gateway's own address, is left out; pasting on the gateway they came from is refused, with the reason as the tooltip.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`; a new test (`TestCanvasDevicePauseThisNode`) covers pausing on this node, that the saved inventory is not changed, resuming and a bad scope.
- Headless Chromium against a mocked API: the device menu reads as above; Pause ▸ This node saves `paused_devices_here: ["sw1"]` and leaves the device enabled; copying All anycast addresses on one gateway and pasting on another adds both.

### Not verified
- Not run against a real cluster or real devices: that a device paused on this node is really not contacted from here (health checks, Ask, changes, captures) rests on the code reading it as disabled and was not seen live. A device paused on this node still shows as answering on another node's pages.
- Delete is "off this gateway" (the Delete key's meaning); the old "Delete device" (out of the inventory) is no longer in this menu.

## [v167] - 2026-11-15 — Theme toggle: Light / Dark / Auto

### Added
- A small icon at the right of the sidebar, just above the "Signed in as" line, switches the theme: **Auto** (half-filled circle; follows the system's light or dark setting, as before), **Light** (sun) and **Dark** (moon). Each click goes to the next one; the icon shows the current choice and its tooltip names it and what a click does. The choice is kept in this browser (localStorage); with storage blocked it lasts until the page is reloaded.

### Changed
- The stylesheet has `:root[data-theme="light"]` and `:root[data-theme="dark"]` copies of the colour sets, so a forced theme wins over the system's. The "no toggle, no stored preference" rule in `CLAUDE.md` and the stylesheet's header comment now say this.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.
- Headless Chromium (system set to dark): Auto → Light turns the page light, Light → Dark turns it dark again, Dark → Auto follows the system, a reload keeps the choice, no page errors.

### Not verified
- Not looked at with the system set to light, in a real browser, or on a phone-width layout. Charts and drawings that take their colours from the page (the topology, Statistics) were not checked in each theme by eye.

## [v166] - 2026-11-15 — Monitor ▸ Devices: tiles and the Devices card only; Monitor ▸ Cluster: no subtitle

### Removed
- **Monitor ▸ Devices** keeps its tiles and the Devices card; every other card is gone: the Target / Ask for / Ask form and its answers, Change ports, Advanced change, Capture packets and Network tools. A device is still asked from its right-click menu on Topology (Ask ▸ …), and a row on this page still has the network tools on right-click. Changing ports, a raw change and packet capture are no longer in the GUI: they stay on the command line (`--device-change`, `--device-raw`, `--device-capture`), over MCP and the API. Clicking a row no longer fills in a target. Help and README say so; the three README screenshots of the old page are no longer referred to (the files are still in `snaps/`).
- The line "Nodes sharing these settings." in the header of the Cluster members card on Monitor ▸ Cluster.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.
- `help_fields_test.go` no longer expects Fields entries for the controls of Monitor ▸ Devices (Target, Ask for, Command, Address), which are gone.
- Headless Chromium against a mocked API: Monitor ▸ Devices shows the five tiles and the one Devices card with no page errors, and a row's right-click menu has Ping, Traceroute, Scan, Lookup and Whois.

### Not verified
- Not run against a real daemon.

## [v165] - 2026-11-15 — Monitor ▸ Gateways: VIP and AGC in the same type

### Fixed
- In a gateway card's header on Monitor ▸ Gateways, "VIP" and its address were both in the monospace font while "AGC" was in the normal font with only its address in monospace. Both now show the label in the normal font and the address in monospace. VIP and AGC also sit a little further right, so they no longer crowd the gateway name.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.

### Not verified
- Not looked at in a browser after the change (a one-line markup change).

## [v164] - 2026-11-15 — [Test] popup: no Run again, no scroll bar

### Changed
- The **[Test]** popup on Monitor ▸ Gateways has no **Run again** button, and no scroll bar: the result wraps in the popup, and its buttons are at the lower right (Close last); the ✕ in its corner is gone. When the gateway already uses real MAC addresses it reads just "Real MAC addresses are on for this gateway: there are no virtual MACs to test".

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`; headless Chromium against a mocked API: the popup for a real-MAC gateway shows the one line, and Use real MAC addresses still saves.

### Not verified
- Not run against a real daemon.

## [v163] - 2026-11-15 — Test virtual MACs is a [Test] button on Monitor ▸ Gateways

### Changed
- **Test virtual MACs** is no longer in the gateway's right-click menu on Topology. Each gateway's card on Monitor ▸ Gateways has a **[Test]** button at the right of its header (not shown when the gateway uses real MAC addresses). It opens the same result popup, now with **Run again**, and **Use real MAC addresses** is still offered when the test says virtual MACs are not delivered. Help is updated.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.
- Headless Chromium against a mocked API: the button sits at the right of the card header, the popup shows the result, and **Use real MAC addresses** saves `real_macs: true` for that gateway.

### Not verified
- Not run against a real daemon (the test itself, which needs a router to ask).
- A read-only user: the button is shown to everyone and the daemon decides whether the test may run.

## [v162] - 2026-11-15 — No menu on the empty drawing

### Removed
- Right-clicking an empty part of the Topology drawing no longer opens a menu (it held New gateway and a few of the gateway's own items, all of which are on the sidebar's ＋ New gateway and the gateway's circle). The click now only clears the selection. Help, and the "No gateway yet" text, no longer mention it.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.

### Not verified
- Not opened in a browser (the handler is one line; the browser's own right-click menu is suppressed there as before).

## [v161] - 2026-11-15 — Gateway menu: Ask devices removed

### Removed
- **Ask devices** (Facts, Interfaces, Neighbors) is gone from the gateway's right-click menu on Topology: all three only opened Monitor ▸ Devices with the question pre-asked. Ask the devices on Monitor ▸ Devices, or one device at a time from its own right-click menu. The gateway menu now reads Statistics, Test virtual MACs (when the gateway does not use real MACs), Edit ▸, Add ▸, Copy ▸, Paste ▸, Pause ▸, Delete. Help is updated.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.

### Not verified
- Not opened in a browser (a deletion of one menu line and its receiving code on Monitor ▸ Devices).

## [v160] - 2026-11-15 — New gateways run on one node; Add ▸ Node no longer lists nodes that left

### Fixed
- Right-click the gateway ▸ **Add ▸ Node** listed "A node that left the cluster (xxxxxxxx)" for every stale entry in the gateway's removed-nodes list (a node that was taken off the gateway, or held back when it joined, and later left the cluster). Those entries are not nodes that can be added. The submenu now lists only nodes that are still in the cluster.

### Changed
- **A new gateway in a cluster runs on the node it was made on, and on no other.** Before, every node in the cluster started serving it at once. The other nodes are put on the gateway's removed-nodes list when it is created (in the web GUI, with the CLI `--canvas-add gateway`, and over MCP); add them where they should serve with right-click the gateway ▸ Add ▸ Node. A gateway that arrives with its own removed-nodes list (a restore, an import, a copy) is left as it is. On a single node nothing changes.
- A node that joins a cluster already started out serving no gateway (that was already so); the help and README now say both things in the same place.

### Added
- **Forget N nodes that left the cluster**, at the bottom of Add ▸ Node when there are such entries: clears them from that gateway. The Add ▸ Node item is greyed out only when there is nothing to add and nothing to forget.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.
- Headless Chromium (netdir) against a mocked API: with one removed node still in the cluster and two stale IDs, the submenu shows the node and "Forget 2 nodes that left the cluster".

### Not verified
- The new-gateway rule (above) has no automated test and was not run on a real cluster: it was only compiled. Check it by creating a gateway on one node of a cluster and looking at the other nodes in Monitor ▸ Cluster / the gateway drawing.
- Not run against a real cluster. The menu code is the same in all three programs but was only opened in netdir's headless run; the Forget click was not followed to a saved config. If the cluster view has not loaded yet (no nodes known), nothing is treated as having left.

## [v159] - 2026-11-15 — Gateway menu reorganised; Statistics opens Monitor ▸ MCP

### Changed
- The gateway's right-click menu on Topology now reads: **Statistics**, **Ask devices** ▸ (Facts, Interfaces, Neighbors; greyed out when the gateway has no devices), **Test virtual MACs** (when the gateway does not use real MACs), then **Edit** ▸ (Gateway, MCP), **Add** ▸ (Device, Node, Anycast address), **Copy** ▸ (All devices, To all gateways), **Paste** ▸ (Device), **Pause** ▸, and **Delete**.
- **Statistics** is new: it opens Monitor ▸ MCP.
- Items that cannot be used are greyed out with the reason as a tooltip: Add ▸ Node when every node already serves the gateway, Paste ▸ Device when nothing is copied (or it is already there), and the Copy items. Before, the Copy and Paste reasons were not shown.
- Menus can now open a third level beside the second (the same menu code as dnsdir), used by Add ▸ Node to list the nodes that were removed from the gateway.
- Help names the new paths (Add ▸ Node, Add ▸ Anycast address).

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.
- Headless Chromium against a mocked API: the menu shows the items above, Add ▸ Node lists a removed node, Paste ▸ Device is greyed out with nothing copied, and Statistics goes to `#mcpusage`.

### Not verified
- Not run against a real daemon; not tried with a read-only user; the menu for an empty drawing, a device, a node and a pill is unchanged. Nothing was clicked through to completion for Edit ▸ Gateway, Edit ▸ MCP, Add ▸ Device, Add ▸ Anycast address or Ask devices (the handlers are the same as before).

## [v158] - 2026-11-15 — History under Operate, plain search and page boxes

### Changed
- **History** (every saved version of the configuration: diff, restore, download, upload, snapshot) is now under **Operate**, between Scheduler and Upgrade, no longer last under Configure. The page, its address (`#history`), permissions and command-line commands are unchanged, so a bookmark still works. The help panel is titled "Operate: History"; the README, `--help` name the new place.
- The filter box on the Log page was drawn in the browser's own style (square corners, no border, another height than the lists beside it) because the style rule for fields did not list `type=search`. It now looks like the other fields.
- The page number in the pager under the long lists is a plain box: the up and down arrows are gone and the number is centred. You still type a page and press Enter or leave the box.
- The same three changes as AnyName v651 to v656.
- Test fix, no behaviour change: `TestMCPUsage` used a fixed date (7 November 2026) and started failing on 15 November, because the usage file it reads back is trimmed to 8 days by the real clock; it now uses the current time. It failed the same way on v157.

### Verified
- `node --check`, `gofmt -l`, `go vet`, `go test -race -count=1 ./...`.

### Not verified
- Not opened in a browser; the look was judged from the AnyName screenshots and the style rules.
- The README screenshot `snaps/history.png` was not retaken, so it may still show the old menu.
- Whether a read-only user's menu shows History under Operate as it did under Configure was not tried.

## [v157] - 2026-11-14 — Certificate page: "shared" tag on the certificate and key

### Changed
- Web GUI ▸ Certificates ▸ "Upload your own certificate": the **Certificate** and **Private key** labels carry the same "shared" tag as the other cluster-wide fields (`sharedTag`, shown only when the node is in a multi-node cluster), because the certificate is replicated from the primary. Nothing else changed; v156 already runs on the cluster, so this is a new version to push to it.

### Verified
- `node --check webui/app.js`, `gofmt`, and `TestFieldHintsAreShort`, `TestEveryPageHasHelp`, `TestVersionIsPlainInteger` and the web tests. The full `go test -race` run was done for v156 (same Go code); `TestMCPUsage` fails there for the date reason given under v156.

### Not verified
- The tag was not looked at in Chromium (light and dark) or in a clustered GUI.

## [v156] - 2026-11-14 — Certificate page: no description text, equal-sized certificate and key boxes

### Changed
- Web GUI ▸ Certificates ▸ "Upload your own certificate": the paragraph under the heading is gone (the same facts — used from the next connection, no restart, nobody signed out, copied to every cluster node — are already in the page's help topic), and the **Certificate** and **Private key** boxes are now the same size (both 7 rows; the key box was 5).
- Nothing changed in how the certificate is shared: it is installed on the primary and copied to every member, and the MCP listeners serve the same certificate as the GUI (both use one `CertManager`).

### Verified
- `node --check webui/app.js`, `gofmt`, `go build`, `go vet ./...` and `go test -race -count=1 ./...` (native, with PAM): everything passes except `TestMCPUsage`, see below.

### Not verified
- The layout was not looked at in Chromium (light and dark).
- `TestMCPUsage` fails here and is not related to this change: it uses a fixed timestamp (6 Nov 2026) and the 7-day report window has moved past it with the real clock. Not touched.

## [v155] - 2026-11-13 — Version bump to test the primary role returning home

### Changed
- Nothing but `VERSION`: a higher version to push through a cluster update, to check that the primary role goes back to the node that had it (v154).

### Verified
- `go build`, `go vet ./...`, `TestVersionIsPlainInteger` and the primary-return tests; gofmt clean.

### Not verified
- The return itself on real daemons: that is what this version is for.

## [v154] - 2026-11-13 — After a cluster update the primary role is back where it was

### Changed
- A primary that restarts into an update still hands the primary role to another member first, but now the role is only lent: the node that was primary when the update began is remembered as its home (`primaryHome`, the file `update/primary_home` in the state directory, carried by the hand-over announcement so it follows the role from node to node in a rolling update, and a node that has to hand the role on prefers the home). When the update is over, the node that holds the role gives it back (`returnPrimaryHome`, run by every sync): nothing queued, nothing installing or restarting, with auto-update every reachable member on the same version (or failed), the home up, not paused and not failed, all for 30 seconds in a row.
- The home is forgotten when its update failed (the role stays where it is, a warning is logged), when it is no longer a member, after 12 hours, and on any promotion by hand or by failover. A restart, shut down, power action or backup restore hands the role over as before and leaves it where it lands.
- The announcement of a new primary has an optional `home` field; older nodes ignore it, so a cluster in the middle of the upgrade to this version works as before (the role stays where it lands until every node runs it).
- `CLAUDE.md`, the README and the cluster help say that promotion is still never automatic, apart from this planned, administrator-started hand-over and its return.

### Verified
- `TestPrimaryReturnsHomeAfterUpdate` (two in-process nodes: the new primary keeps the home, the role stays while an update is queued and goes back when it is over, a plain restart and a manual promotion leave nothing to return), `TestPrimaryHomeSurvivesARollingUpdate` (three nodes, two hand-overs in a row, the role ends at the first node), `TestPrimaryReturnTarget` (each condition, and the home being preferred as successor). Full `go test -race`, `gofmt`, `go vet`, no-cgo vet and tests, cross-compiles.

### Not verified
- Not run on real daemons with a real `--update-push all` (builds and re-execs), only with the in-process clusters of the tests; the 30 seconds of settling and the interaction with the canary soak were not exercised live.

## [v153] - 2026-11-13 — v152 failed to build on a node whose source tree still had apiroutes.go

### Fixed
- v152 deleted `apiroutes.go` and `apiroutes_test.go`. An update whose source tree was made by copying v152 over an older tree kept the old file, which no longer compiled (`undefined: apiRoute`), so the update failed with `go build failed`. Both files are back as empty stubs (`package main` only), so any such tree overwrites them and builds. The route list itself stays removed.
- `CLAUDE.md`: a file is never deleted from the tree in a release, only emptied (a release that has to remove a file leaves an empty stub), because trees are copied over each other.

### Verified
- A clean extract of the archive builds; the same tree with the v151 `apiroutes.go` and `apiroutes_test.go` copied over a v153 tree is overwritten by the stubs and builds. `gofmt`, `go vet`, `go test -race`, no-cgo vet and tests, cross-compiles as in v152.

### Not verified
- The GUI updater itself was not run here; its source staging (`ExtractSource`) replaces the tree whole, so the stale file must have come from the tree that was uploaded.

## [v152] - 2026-11-13 — An MCP caller can only ask the gateway about its devices

### Changed
- The MCP tools are now the device tools (`device_*`, including `device_change`, `device_change_raw`, `device_capture` and `device_troubleshoot_user`), `list_devices` (the device list and each device's health), the network tools (`net_*`) and the cluster status (`list_nodes`, `get_topology`). Nothing else about netdir itself can be asked.
- Removed: `get_gateways`, `get_alerts`, `get_lldp`, `get_host_stats`, `get_schedule`, `get_updates`, `get_node_status`, `get_config`, `list_api` and `api_get`. `api_get` and `get_config` were the way to any route of the GUI's API (configuration, versions, cluster, BGP, users ...); with them gone an MCP caller has no way to read a route other than the ones the remaining tools make.
- No tool takes a `node` any more (`get_topology` was the last): the node that serves the endpoint answers, and a call with a `node` argument is refused ("tools take no node argument"). Device tools already ran on the serving node only.
- A caller limited to some devices lost nothing it had before except the removed tools; `scopedOffTools` is now `device_troubleshoot_user` and the network tools.
- Dead code removed with the tools: `apiRequest`, `apiRequestOn`, `restoreHidden`, `apiroutes.go` (the generated route list) and its test.
- The GUI, the CLI and the GUI's API are unchanged: an administrator still reads and changes all of it there. README, the MCP help topic and the server instructions say the same.

### Verified
- `gofmt -l .` clean, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, and the cross-compiles of the release list.
- `requireGateTools` (`mcp_test.go`), used by the read-only, rw, limited-key and barred-route tests: the tool list has the device, list and status tools and nothing else, each removed tool answers "unknown tool", and a `node` argument is refused on `list_nodes`, `get_topology` and a device tool. The tests that used `get_config`, `api_get`, `get_lldp` or `get_alerts` now check that those are gone and that no device secret, key or gateway secret reaches a caller through the tools that remain.

### Not verified
- Not run against a real MCP client; an assistant configured with the old tool names will get "unknown tool" for the removed ones.
- `tools/leaktest.sh` was not run (no driver or masking change).

## [v151] - 2026-11-13 — An MCP caller cannot read logs, accounts or keys

### Changed
- MCP callers (any key or allowed source, read-only or rw) can no longer read log content: the `get_log` tool is gone, and `api_get` refuses `/api/log`, `/api/tshoot/*` (the troubleshooting bundle, which holds the MCP content log), `/api/users*`, `/api/backup*`, `/api/mcpusage` and `/api/cluster/token*` (`mcpbar.go`, checked in `mcpWriteGuard`, so also through `/api/proxy`). `list_api` no longer lists them.
- `get_config` and `api_get /api/config` leave out the MCP keys and allowed sources, the login groups and the LDAP and SSO settings (`mcpDropAccounts`).
- A netdir, DNS or NTP Director device no longer answers `show log`.
- The GUI and CLI are unchanged: a signed-in administrator keeps every one of these.

### Verified
- `mcpbar_test.go`: tools/list without `get_log`, `api_get` refusals for each barred route, `list_api` without them, the account fields dropped.

## [v150] - 2026-11-13 — The troubleshooting bundle includes the MCP content log

### Added
- `netdir --tshoot` and the Node menu's tshoot download now always include the MCP content log of each node as `netdir/mcp-content.log` (`tshootcontent.go`): the newest entries of `mcp-content.log` and `mcp-content.log.1`, up to 4 MB, oldest first, whole lines only. Requests and replies are in it as the callers were given them (secrets hidden and the caller's privacy level applied by the endpoint); the bundle then removes secrets again over every key (`redactJSON`) and every string, including the text of a reply (`redactText`), and counts them in the README's "secrets were removed" line. A note line says when the log is off or has no entries yet; entries kept from before it was turned off are still included. There is no switch: it is always in.
- When the bundle is still too large for the cluster channel (3 MB compressed per node), the larger of `netdir/log.txt` and `netdir/mcp-content.log` loses its older half, until it fits; the content log then starts with a line that says older entries were cut.
- `webui/help.js` (the tshoot topic), `netdir --help` and the README say so.

### Verified
- `gofmt -l .` (nothing), `go vet ./...`, `go test -race -count=1 ./...` (all packages pass, with the PAM headers), `CGO_ENABLED=0 go vet ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386` and `riscv64`. New tests in `tshootcontent_test.go`: secrets in keys, in nested replies and in non-JSON lines are removed while the rest stays; the off, empty and old-entries states; the newest entries are kept within the cap and no line is cut in the middle; halving; and a real `TshootNode` bundle that holds the log and lists it in its README.
- A live run: the daemon built with PAM, a request to `/mcp` with a key and a `password` argument, then `netdir --tshoot --tshoot-file`: the bundle held `netdir/mcp-content.log` with the request and reply and neither the password nor the key.

### Not verified
- A cluster of several nodes (each node's own log in its own folder) was not run live; the cluster bundle test covers the folder per node for the other files. The size cut was tested on the helper, not with a real 3 MB bundle. `device42` was confirmed against a real server by the owner; `smax` has not been run against a real tenant.

## [v149] - 2026-11-13 — MCP page text fixed, the content log's path is stated, and the checks the process asks for were run

### Fixed
- The content log's fields on Configure ▸ MCP had labels that were not plain English and one of them wrapped, so the fields were out of line. They are now **Log all MCP requests and replies**, **Log size limit** (1 to 1000 MB) and **Entry size limit** (1 to 8192 KB). The hint I had added under the switch is gone (the notes in CLAUDE.md allow a few words of hint only when asked for).
- Nothing said where the content log is. `webui/help.js` (the MCP topic), the README and `netdir --help` now give the path, `/var/lib/netdir/mcp-content.log` (the state directory, `--state-dir`; the older half is `mcp-content.log.1`).
- The Notes column of the allowed sources is wider (`style.css`), so a longer note is not cut off.

### Added
- `netdir --help` lists the three `mcp_log*` settings and the `#` note of an `mcp_acl` entry. `webui/help.js` describes the `device42` and `smax` drivers in the device list.

### Verified
- `gofmt -l .` (nothing), `go build`, `go vet ./...`, `go test -race -count=1 ./...` (all three packages pass, including the update build test, now that the PAM headers are installed), `CGO_ENABLED=0 go vet ./...`, `sh tools/leaktest.sh` (34 platforms, 1339 recorded answers, no leak), and cross-compiles for `linux/amd64`, `arm64`, `arm`, `386` and `riscv64`.
- A live check: the daemon built with PAM, a real PAM user in a `netdir` group, signed in with Chromium (`playwright`) in light and dark, Configure ▸ MCP drawn with its content log fields, a source with a note, a disabled source and a key with a note. The card is 1520 px wide, the fields line up and no script error appeared. A request to `/mcp` with a key wrote a line to `mcp-content.log` (mode 0600) that holds the request and reply and not the key, and a request with a wrong key was logged with status 401.

### Not verified
- The two new drivers (`device42`, `smax`) have still not been run against a real Device42 or SMAX; they come from the vendors' documentation and a TLS stub. The content log was not checked on a cluster of several nodes. The IPv6 and multi-node checks that CLAUDE.md lists for other areas were not needed for this change and were not run.

## [v148] - 2026-11-13 — Configure ▸ MCP: a wider card, and notes on allowed sources and keys

### Added
- A **Notes** column on the allowed sources and on the keys (Configure ▸ MCP). A note is up to 200 characters on one line and changes nothing. For a key it is `mcp_keys[].notes`. For a source it is written after a `#` at the end of the entry (`"10.0.0.20 rw # mike's laptop"`); every reader of an entry (`aclBody` in `mcp.go`) ignores it, so a word in a note such as `rw`, `disabled`, `until=` or `devices=` is only text, and entries of one address that are merged keep their notes joined with `; `. Tests: `mcpnotes_test.go`.

### Changed
- The Configure ▸ MCP card is wider: the page may be up to 1600 px instead of 1150 px, and its tables use the whole card instead of stopping at 63 rem (`style.css`, `.mcpcard`).

### Not verified
- The wider layout and the Notes columns were not looked at in a browser, only checked as code and by the Go tests. The browser rule uses `:has()`, which older browsers lack (they keep the old width).

## [v147] - 2026-11-13 — Device42 and Micro Focus SMAX drivers, and a content log for the MCP endpoint

### Added
- **`device42`** (`device/device42.go`): Device42 over its REST API (`/api/1.0`, `/api/2.0`), user name and password. Facts, interfaces, `show devices|device|ips|subnets|vlans|racks|buildings|macs|hardwares|vendors|customers`, `device_api_get`, and `device_change_raw` (POST/PUT/PATCH/DELETE, form fields or JSON; passwords, users, keys, tokens and authentication are refused). Also an **import source** (Import ▸ Devices).
- **`smax`** (`device/smax.go`): Micro Focus (OpenText) Service Management Automation X over its REST API, option `tenant`, user name and password of an integration or database-authenticated user. `show requests|incidents|changes|problems`, `show request ID`, `device_api_get` below `/ems/{Request,Incident,Change,Problem}`, and `device_change_raw` as `POST /ems/bulk` (CREATE or UPDATE only; no deletes, no people, groups, roles or settings).
- **MCP content log** (`contentlog.go`): with `settings.mcp_log` on (Configure ▸ MCP ▸ Content log), everything that goes into and out of the MCP endpoint is written, one JSON line per request, to `mcp-content.log` in each node's state directory. Size limit `mcp_log_mb` (1 to 1000, default 50, two files of half), per-entry limit `mcp_log_entry_kb` (1 to 8192, default 256). Off by default. Replies are written as the caller got them; secrets in requests are hidden; the `Authorization` header is never written; refused requests are logged without a body.

### Verified
- `go vet` and `go test -race -count=1 ./device` (new stub tests for both drivers, including write guards, session renewal and import), `CGO_ENABLED=0 go test` of the main package for the content log, help and hint tests.

### Not verified
- Neither driver has been run against a real Device42 or SMAX; both were written from the vendors' documentation and a test stub. `TestUpdateBuildApplyAndRollbackGuard` could not run where PAM headers are missing. `sh tools/leaktest.sh` was not run (it needs the cgo build).

## [v145] - 2026-11-12 — The Meraki lookup cache no longer hashes the API key (CodeQL alert 4)

### Changed
- The key of the Meraki lookup cache (`device/meraki.go`, `idKey`) was a SHA-256 of the device's address, port, organization and the dashboard **API key**. It stayed in memory and was never stored, shown or compared, but a fast hash of a secret is what the code scanner flags. It is now made from the login's **name** and the device's name instead, so no secret goes into it; the cache is already emptied whenever the configuration changes (`mgmt.go`), so a changed key under the same login name cannot return an old answer. Entra's cache key already held no secret.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. New test `TestMerakiCacheKeyDoesNotUseTheKey`: the same login with another key gives the same cache key, another login gives another.

### Not verified
- Whether the CodeQL alert clears is known only after the next scan on GitHub. Alerts 3 and 6 were not changed (a protocol requirement and a deliberate diagnostic) and are for dismissal in GitHub.

## [v144] - 2026-11-12 — Add device ▸ Devices from inventory lists only devices that have a login

### Changed
- On the Topology page, Add device ▸ *Devices from inventory* (renamed from *Devices of the inventory*) now lists only the devices that have a login (and the network-tools device, which needs none). Devices still without one, such as freshly imported ones, are left out until a login is given in Configure ▸ Devices.

### Verified
- `node --check webui/app.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.

### Not verified
- The dialog itself was not driven in a browser; the change is one filter on the list it is built from.

## [v143] - 2026-11-12 — The Configure page no longer drops devices that have no login (the real cause of the imported devices disappearing)

### Fixed
- **Imported devices disappeared whenever anything was saved on a Configure page.** The Devices table marks a row red when it has no login, and the page left every marked row out of what it saved, so the first save of any Configure field (they save when you leave a field) wrote the configuration without every device that had no login. Imported devices have none until you give them one, and devices you gave a login kept their place, which is why the 50-odd devices with logins stayed. The history of the cluster shows it: each removal is a save by the GUI user with an empty note (the Configure page), 35 to 60 seconds after an import, with a valid check token, so it was not a stale page. A device is now left out only when it has no name or no address; one with no login stays, still marked red.
- Earlier fixes in v138, v140 and v141 (the check token, refusing a save without it, the primary's check of a replica's save) are real protection against stale pages but were not the cause of this.

### Verified
- `node --check webui/app.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. In headless Chromium with a mocked API holding two devices with no login (and one with): leaving the Address field saved all of them; with the previous page code the same action saved only the one with a login.

### Not verified
- Not run against the real cluster. The same mocked page raises an error in the alert-rules table that comes from the mock. The other tables of Configure (logins, access lists) still leave out their incomplete rows when saving; only Devices was changed.

## [v142] - 2026-11-12 — Picked rows in a list stay coloured when the list loses the focus

### Fixed
- In a multi-pick list (Add device ▸ Devices of the inventory, and every other list where several rows can be picked), the picked rows turned black as soon as something else got the focus, for example ticking Enable. They now keep the accent colour, light and dark (`select[multiple] option:checked` in `style.css`).

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. In headless Chromium (light and dark), with two rows picked and a checkbox ticked: the picked rows stay in the accent colour.

### Not verified
- Not looked at in Firefox or Safari.
- A report that the imported devices disappear when some are assigned to a gateway was not reproduced: a cluster test (import on a replica, then assign one device to a gateway from the replica) keeps all devices on both nodes. A case in the cluster test now keeps that path covered.

## [v141] - 2026-11-12 — A replica's save can no longer overwrite what the primary has (imported devices disappearing, again)

### Fixed
- **Imported devices disappeared a fourth time, with every node on v140.** In the tshoot bundle the import (256 devices) was applied on the primary at 00:13:24 and removed again at 00:14:00, originating on the primary. A save made on a **replica** was checked against the replica's own copy of the settings, which can be a moment behind the primary's, and was then forwarded to the primary, which applied it without any check. A page on a replica that had not yet seen the import therefore wrote its old device list over it. The page's `base` now travels with the forwarded save and the primary refuses it (409, nothing written) when its own settings are not the ones the page read; the replica passes the refusal on, and the page shows what is saved.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. New case in the cluster test: the primary changes, a replica still on the old copy saves with the old base: refused, the primary keeps its change.

### Not verified
- Not run on the real cluster, and not with live daemons. The bundle holds only the replica's view (history entries say "cluster sync"), so which node and page made the 00:14:00 save is inferred from the code path, not read from a log of the primary.

## [v140] - 2026-11-11 — Imported devices can no longer be wiped by an old page; SNMP (ios) devices are no longer reported unreachable

### Fixed
- **Imported devices disappeared a third time.** In the tshoot bundle the removal of 256 devices was saved with no note, so it came from the Configure page, not Topology: a Configure tab left open from before v138 still ran the old page code, which sends no `base`, and the Configure page never reloads itself. `PUT /api/config` now **refuses (409) any save that carries no `base`** ("this page is older than the daemon … reload it (Ctrl+F5)"), nothing is written, and the refusal is logged. `dry_run` is unchanged. A script that means to replace the configuration sends `"base": "force"`.
- Every device of platform **ios** (classic IOS over SNMP) showed red, "the API port does not answer: connect: connection refused", although `snmpwalk` to it worked. The health check opened a TCP connection to the device's port first, and SNMP is UDP, so nothing ever listens there. An SNMP device is now asked over SNMP instead (the same request as its facts, one datagram), every check, with no TCP connection: an agent that answers is green; one that does not is red with "no answer over SNMP (the device is unreachable, or the community or the ACL is wrong)", because SNMP does not tell those apart. The community never appears in the text.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. `TestWebConfigSaveRefusesStaleBase` now also covers a save without `base` (409, nothing changed) and `force` (saved). New test `TestMonitorSNMPDeviceIsNotDialled` against the SNMP stand-in agent: no TCP connection is tried, the right community gives ok with the facts, the wrong one gives bad with the new text and without the community.

### Not verified
- Not run against a real IOS switch (the stand-in agent answers SNMP v2c only; v3 goes through the same request). The check now sends one SNMP request per device every check interval (default 3 minutes), so a few hundred ios devices mean a few hundred datagrams per round, five at a time.

## [v139] - 2026-11-11 — Login suggestions in the Devices table

### Added
- In Configure ▸ Devices, the **Login** column of the Devices table lists the matching logins as you type (the browser's own list under the box; it filters as you type and picks with a click or the arrow keys). The names are read from the Logins table below it when the box gets the focus, so a login you have just added and not saved yet is offered too. Any name can still be typed. Help text added.

### Verified
- `node --check webui/app.js` and `help.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. In headless Chromium with a mocked API: the Login box is attached to a list holding exactly the three logins of the Logins table.

### Not verified
- The dropdown itself was not looked at (the browser draws it outside the page, so a screenshot does not show it), and the case of a login added in the Logins table and not yet saved was not driven. The same mocked page raises an error in the alert-rules table (`rules` undefined) that comes from the mock, not from this change.

## [v138] - 2026-11-11 — A stale page can no longer overwrite the configuration (imported devices disappearing)

### Fixed
- **Imported devices disappeared.** The GUI saves the whole configuration, from the copy the page read when it was opened. A Topology page opened before an import therefore wrote its old copy back at its next change and removed the imported devices with it: in a tshoot bundle the import added 257 devices at 22:17 and a Topology save made from a page opened hours earlier removed 259 devices (the imports and `network_tools`) at 22:20.
- `GET /api/config` now returns `base`, a token of the shared settings it read, and `PUT /api/config` takes it back as `base`. When the shared settings are not the ones the page read, the save is refused with **409** and nothing is written (`Mgmt.PutConfigBase`, under the same lock as the save, so two saves cannot both pass). A save with no `base` was allowed in v138; since v140 it is refused (see v140). The reply to a successful save carries the new `base`.
- The **Topology** page keeps the token, sends it with every change, and after a 409 reads the saved configuration again and shows it (your change is dropped, and the next one goes through). The **Configure** pages send it too and show the 409 as "Not saved: …".
- Limits: a replica compares with its own copy of the shared settings, which the primary updates within seconds, not with the primary's at that instant; and a page that is refused loses the change it was making (it is shown the saved state, nothing is merged).

### Verified
- `node --check webui/app.js` and `help.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. New test `TestWebConfigSaveRefusesStaleBase`: GET has a base; a save with it works and returns a new one; a save with the old one is 409 and leaves the devices as they were; the new one works; a save with none works. In headless Chromium with a mocked API: the Topology page sends its base, reads the configuration again after a 409 and sends the new base with the next change.

### Not verified
- Not run on a real cluster, so the replica path (a save on a replica refused because the primary's change had not arrived yet, and the forward to the primary) was not exercised. The Configure pages were not driven in a browser. Devices that were already removed are not brought back by this: run the import again (it adds only the ones missing).

## [v137] - 2026-11-11 — The topology filter: in the top bar, and no longer matching tags by a plain word

### Changed
- The Topology filter box is in the top bar, at the left, level with the Node picker, and has the same look and height as it (the box and the picker are both 2.3 rem high on every page that has the bar). It was above the drawing. Its text is kept while you move between pages.

### Fixed
- Typing `observ` in the filter left every imported device on the map: an imported device carries the tag `source=observium` (the name of the server it came from), and the filter searched tags. The filter now looks at the name, address and platform only. A tag is searched with `tag:` before the word (`tag:env=prod`, `tag:source=observ`); every word must still match. The help text says so. The cluster's nodes and the anycast addresses are not devices and are always drawn.

### Verified
- `node --check webui/app.js` and `help.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. In headless Chromium (light and dark, mocked API, two nodes): the filter and the picker are the same height and on one line, the filter is in the bar and not on the page, with two devices tagged `source=observium` `observ` shows none of them and `tag:source=observ` exactly those two, and the name, address, platform and `tag:` words work together; the box keeps focus while typing.

### Not verified
- Not driven against a live daemon with the real imported devices, and not on a narrow window (the bar's layout there was not looked at).

## [v136] - 2026-11-11 — A filter box on the topology map

### Added
- **Filter devices** box at the top left of the Topology map. Typing hides every device of the gateway that does not match; a device matches when its name, address, platform or a tag holds every word typed (case ignored). Clearing the box shows them all. The text is kept while you move between pages. While a filter is on, devices cannot be dragged to a new place (the order shown is not the saved order). The filter changes only what is drawn: nothing is saved or sent. The help page of Topology says so (`webui/help.js`).

### Verified
- `node --check webui/app.js` and `help.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.
- In headless Chromium (light and dark, API answers mocked, no page errors): five devices; `prod` leaves fw1, `dc1 fw` fw1, `10.0.5` switch1 and ns1, `PROXMOX` the two Proxmox platforms, `zzz` none, and clearing the box brings all five back; the box keeps focus while typing.

### Not verified
- Not driven against a live daemon, and not with a long list of devices on several rows. Shift-click selection while a filter is on picks from the devices shown.

## [v135] - 2026-11-11 — The network tools reach a gateway this node does not serve

### Fixed
- `net_ping`, `net_mtr`, `net_scan` and the other tools failed with "no node that serves gateway … can be reached" for every gateway this node does not serve; only the gateways it serves worked. Two causes: the node was looked for by matching the gateway's member addresses against the cluster nodes' addresses, which this node's own view of such a gateway does not carry, and a read-only key's POST through `/api/proxy` was refused as a change. The node is now chosen as the Topology page chooses it (`servingPeers`: a reachable node that serves the gateway well, then one that serves it degraded) and the node's own cluster address is used. When no other node reports the gateway as running, the error says so.
- A read-only caller (an MCP key or a node relaying one) may start the two look jobs (`/api/nettool`, `/api/scan`) through `/api/proxy` too, judged by the path it carries; every other relayed POST is still refused for it, and so is a read-only GUI user.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`. New tests: `TestToolsNodeFor` (served here, degraded here, by a peer, paused here, nobody, single node) and `TestReadOnlyJob` (the allowed and refused paths, direct and through the proxy).

### Not verified
- Not run on a real cluster: the relay of a job to a second node, and the polling of its result through it, were not exercised end to end (the sandbox has one node). The choice of node is tested on node lists, not on a live cluster.

## [v134] - 2026-11-11 — nmap scans accept a host name; ping options, port, TLS, ARP and Wake-on-LAN tools, dig without dig

### Fixed
- `net_scan` (and `POST /api/scan`, `--scan`) refused a host name such as `ns1.cush.local` ("not an IP address"). The scan takes an address or a host name now; the name is checked label by label (no spaces, no leading `-`, not a range) and nmap looks it up on the node that runs the scan, so it uses that node's DNS. Addresses are checked as before. The job is remembered under the lower-case name.

### Added
All of these are used with a `gateway` argument as the other `net_*` tools are, run on a node that serves the gateway, and are not offered to a key limited to some devices.
- **`net_ping` options** `count` (1 to 20, default 4), `size` (payload 8 to 65500) and `df` (don't fragment, `-M do`): find a path's MTU for VPN and tunnel problems (the largest size that passes is the path MTU less 28 bytes, 48 for IPv6). The time allowed grows with the count. A job with options is its own job, not the plain one.
- **IPv6 / IPv4 choice** `family` (4 or 6) for `net_ping`, `net_mtr`, `net_port` and `net_tls`: a name is looked up for that family only, an address of the other family is refused. A ping to a name now begins with `name → address (IPv4|IPv6)` so the family used is visible.
- **`net_port`** (`GET /api/portcheck`): TCP connect to up to ten ports, each open, closed (refused) or filtered (no answer in 4 s), with the connect time. Written in Go, no program needed.
- **`net_tls`** (`GET /api/tlscheck`): TLS handshake with a host and port (optional `sni`): protocol, cipher, ALPN, the chain with subject, issuer, valid from/to, days left, names, key and signature, whether this node's roots trust it for the name (`trusted`, `verify_error`), and a `warning` when it has expired or expires within 30 days. Any certificate is accepted for the look. Go, no program.
- **`net_arp`** (`GET /api/arp`): the MAC the node has for an IP on its own segment, with the interface and subnet (IPv4 from `/proc/net/arp`, IPv6 from `ip -6 neigh`). An address on a subnet of the node that is not in the table is asked for with one UDP datagram first; an address on another segment is reported as not on a segment of the node.
- **`net_wake`** (`POST /api/wake`): a Wake-on-LAN magic packet (UDP port 9) to 255.255.255.255 or a given IPv4 broadcast address. It powers a machine on, so unlike the others it is a write tool: a read-only key is refused, and a read-only GUI account cannot POST it.
- **dig without dig**: when `dig` is not installed, `net_dig` answers an address's name (reverse DNS, PTR) and A, AAAA, MX, NS, TXT, CNAME with the node's resolver (or the given server on port 53), marked with a note; the other types still need dig.
- Routes `/api/portcheck`, `/api/tlscheck`, `/api/arp`, `/api/wake` are relayable to another node; `POST /api/wake` joins `/api/nettool` and `/api/scan` in the MCP write guard.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.
- Tests: a scan of `NS1.cush.local.` with a stand-in `nmap` receives `-- ns1.cush.local`; ping's exact arguments for count, size, df and family (stand-in `ping`, through the MCP tool and the node's API); every bad count, size, family, port, SNI, IP, MAC and broadcast value is refused; the port check against a real listener (open) and a closed port; the TLS check against a Go TLS test server (TLS 1.3, not trusted, no warning) and a plain-text port (handshake error); `net_wake` refused for a read-only key; reverse DNS through the resolver with no `dig` on the PATH.

### Not verified
- Never run with the real `ping` options (`-M do`, `-s`), `mtr`, `nmap`, `dig` or `curl`, nor across a cluster. Not sent: a Wake-on-LAN packet to a real machine (the sandbox has no peer; only the argument checks and a built packet are covered), and an ARP lookup that finds a neighbour (the sandbox's table is empty) or the IPv6 neighbour read (`ip -6 neigh`, no IPv6 in the sandbox). A TLS chain with an intermediate, and the expiry warning, were not exercised. The GUI has no pages for these tools.

## [v133] - 2026-11-11 — A "tools" device: ping, mtr, dig, curl, whois and nmap for the assistant

### Added
- **Platform `tools`** (`device/tools.go`): one device, no address and no login (Devices ▸ Add ▸ *Network tools*). Adding it to a gateway's devices enables the network tools for that gateway. Its health shows which of `ping`, `mtr`, `nmap`, `dig`, `curl` are installed on the node.
- **MCP tools `net_ping`, `net_mtr`, `net_dig`, `net_curl`, `net_whois`, `net_scan`** (`mcpnettools.go`) with a `gateway` argument (label or number): "scan 10.1.1.1 from paris" is `net_scan` with `host` and `gateway` `paris`. The job runs on a netdir node that serves that gateway (this node when it does, otherwise a peer through the cluster relay). `gateway` may be left out when only one gateway has the tools; a gateway without the device is an error that names the ones that have it. Ping 15 s, mtr up to 2 min, nmap up to 2.5 min; a longer job is returned as running with a note.
- **All six work with a read-only key** (none changes configuration) and none is offered to a key limited to some devices. `POST /api/nettool` and `POST /api/scan` are let through for in-process (MCP and relayed) read-only requests only; a read-only GUI user is still refused every POST.
- **dig** (`dig.go`, `GET /api/dig`): one query with `+time=3 +tries=1`, no shell; name checked label by label (or an address, asked with `-x`); type one of A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, DS, DNSKEY, NAPTR, TLSA, SPF (not ANY); optional DNS server address; output cut at 8 KB.
- **curl** (`curl.go`, `GET /api/curl`): http/https only, no user info in the URL, HEAD (default) or GET, optional follow (at most 3 redirects) and optional skip of certificate checks; 15 s, 1 MB, output cut at 16 KB, timings appended. No shell.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.
- `TestMCPNetTools*`: read-only and read-write keys are offered all six, a limited key none; refused hosts, names, types, servers and URLs never reach a program; gateway resolution (only one, none, wrong one); with stand-in programs first in PATH the exact arguments passed to `dig` and `curl` are asserted and a public address in the answer is masked.

### Not verified
- Not run with the real `ping`, `mtr`, `nmap`, `dig` or `curl` (none installed in the sandbox; only stand-ins), not across a real cluster (the gateway-to-node mapping and the relay of the POSTs), and the GUI was not opened in a browser. dig and curl have no GUI; the Network tools page is unchanged.

## [v132] - 2026-11-10 — Active Directory lookups under Ask

### Changed
- On an Active Directory device the right-click menu has **Ask ▸ Look up user / Look up computer / Look up group** (they were beside Ask), and **Troubleshoot user or host** is gone from that device's menu. The troubleshooting itself is unchanged (it still adds the directory record when an Active Directory device exists; it is started from the Entra or Panorama device, the CLI, or MCP).

### Verified
- `node --check webui/app.js` and `help.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.

### Not verified
- Not opened in a browser.

## [v131] - 2026-11-10 — Active Directory fills in port 636; the port hint is gone

### Changed
- Picking **Active Directory** in the device form fills the port with 636 (LDAPS), as the other platforms fill theirs; a port typed by hand is kept, and 636 is the default so it is not written to the configuration.
- The line under the Port field ("Default 443 (Proxmox VE 8006).") is removed; the defaults are in `webui/help.js`.

### Verified
- `node --check webui/app.js`, `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.

### Not verified
- Not opened in a browser. With the option `starttls=true` the driver uses 389 when no port is written, so a StartTLS device must have its port set to 389 by hand (the form fills 636 for the platform).

## [v130] - 2026-11-10 — Active Directory in tshoot, and searches for accounts that need a look

### Added
- **tshoot adds the Active Directory account.** With an `ad` device in the inventory, `tshoot user` (and `device_troubleshoot_user`) adds `directory`: the account the name matches (sign-in name, mail address or display name; the account name Entra gave is tried when the name as typed finds nothing; up to 3, best match first) with enabled, locked out, when the password last changed, last sign-in, groups, manager, title. `tshoot host` adds the computer account (DNS name, operating system, last sign-in, manager). `directory_device` names the device. No device is not an error and adds no note; no match is a note; `ad=NAME` (MCP `ad`, GUI right-click ▸ Troubleshoot user or host on an Active Directory device) picks one when there are several, and a name that is not there is an error. It reports the account, not where the user is signed in: the directory does not hold that.
- **Active Directory searches** (Show on an `ad` device): `show locked` (users with a lockout time; one older than the lockout duration has expired), `show disabled` (disabled users that are still members of groups), `show stale users|computers [DAYS]` (enabled accounts with no sign-in for DAYS days, 1 to 3650, default 90, or never, created before that). Up to 50 lines, the longest without a sign-in first, and a line when there are more. The LDAP filter got `not`, `>=`, `<=` and the bit-and matching rule for this.
- `device.DirectoryLooker` (`DirUsers`, `DirComputers`) is the interface the troubleshooting asks.

### Changed
- Skipping the LDAPS certificate check needed nothing new: an Active Directory device takes the same **Certificate: skip check** (`insecure`) or CA PEM as every device; README says so under the driver.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`; `node --check` on `app.js` and `help.js`.
- `TestADLookups` (the test directory now evaluates `not`, `>=`, `<=` and bit-and): `show locked`, `show disabled` (one without groups is not listed), `show stale computers` and `users 30` (an old account is listed; a recent, a disabled and a brand-new one are not), refused day counts, and the records `DirUsers` and `DirComputers` give.
- `TestTroubleshootWithActiveDirectory`: no `ad` device means no `directory`; with one, a user's record (disabled, locked out, groups) and a host's computer record are added next to Entra and Meraki, which are still asked; a named device that does not exist is an error.

### Not verified
- Not run against a real domain controller: the bit-and rule and the time filters follow Active Directory's documentation but only the test directory has answered them. `lastLogonTimestamp` is replicated every 9 to 14 days, so "stale" means at least that long; accounts are not checked against the lockout duration. A search that matches more than the controller's size limit is cut and says so; the order inside a cut result is the controller's.
- GUI: the new menu item was not opened in a browser.

## [v129] - 2026-11-10 — Active Directory device: look up users, computers and groups

### Added
- **Platform `ad` (Microsoft Active Directory)**, `device/ad.go`, standard library only (a small LDAP client: BER from `snmp.go`, RFC 4511). The device is a domain controller; the login is `user@domain`, `DOMAIN\user` or a DN with its password. Always TLS: LDAPS on 636, or StartTLS on 389 with the option `starttls=true`; there is no clear-text bind, and a login without a password is refused (no anonymous bind). Certificate as for every device (skip check or CA PEM). Option `base` is the search base, by default the controller's `defaultNamingContext`.
- **Show:** `show user NAME`, `show computer NAME`, `show group NAME` (up to 10, in detail; exact match first), `show users NAME` and `show computers NAME` (up to 50, one line each), `show domain`. NAME is a sign-in name (`jsmith`, `CORP\jsmith`, `jsmith@corp.example.com`), a mail address, a display name or a computer name or DNS name, or the start of one. The answer is plain text. A user: name, account, sign-in name, mail, enabled, locked out, title, department, company, office, phone, manager, employee ID, when the password was last changed (labelled "Sign-in changed", because the secret-word filter hides any line that says "password"), whether it never expires, last sign-in, bad sign-ins, expiry, groups. A computer: DNS name, enabled, operating system, last sign-in, location, manager, groups. A group: members (count and the first 30). Facts are the controller's DNS name and the domain level.
- GUI: right-click an Active Directory device ▸ **Look up user**, **Look up computer**, **Look up group** (a name box; the answer is the text popup). The platform is named "Active Directory". README, `webui/help.js` and `main.go` usage updated.
- It is also the answer to every device read tool (`device_show` with the commands above, `device_facts`).

### Security
- The filter is built as a structure (BER: equality, prefix, and, or), never as text, so a name cannot add to it; names are also limited to letters, digits and a few punctuation marks (no `*`, `(`-filters, `|`, `;`).
- Only a fixed list of attributes is asked for. Passwords and hashes (`unicodePwd`, `userPassword`), LAPS (`ms-Mcs-AdmPwd`, `msLAPS-*`), security descriptors and SIDs are not on it, so the controller cannot return them; the test checks that no search asks for one. Show output also goes through the usual secret filter, and over MCP the usual masking (a mail address shows its name part only).
- Nothing is changed: `device_change_raw` on an Active Directory device is refused.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`; `node --check` on `app.js` and `help.js`.
- `TestADLookups` (against an LDAP directory written from RFC 4511 over TLS, that evaluates the filters it receives; once with LDAPS and once with StartTLS): facts; a user with its groups and manager, an exact match before a prefix match, `DOMAIN\name`, a disabled and locked-out user, the list form, a computer by DNS name and by account name, a group and its members, `show domain`, no match, names that are refused do not reach the directory, no secret attribute is asked for and none is shown, one bind per driver, a change is refused. `TestADLogin`: no password is refused, a wrong one is a clean error without the password, and a directory that does not speak TLS gets no password.

### Not verified
- Not run against a real domain controller: the LDAP messages follow RFC 4511 and the attribute names are Active Directory's schema, but only the test directory has answered. Paged results are not used: a search is cut at the controller's or the driver's limit (the answer says there are more matches). Referrals to other domains are not followed, so a user of a child domain is found only when its domain controller is added as a device.
- "Last sign-in" is `lastLogonTimestamp`, which Active Directory replicates only every 9 to 14 days; "locked out" is the lockout time being set, not checked against the lockout duration. Nested group membership is not expanded.
- `tshoot` does not use it: Active Directory has no record of which computer a user is on, so it is a lookup device only.
- GUI: the menu items and the form were not opened in a browser.

## [v128] - 2026-11-10 — Right-click ▸ Ask shows text, not JSON

### Changed
- The answers of a device's right-click **Ask** menu (and the text card of Monitor ▸ Devices) that came as JSON are now plain text: **Ports**, **Routes** and **VLANs** are aligned tables like Interfaces and Neighbors already were; **LLDP and CDP details**, **Routing protocols**, **Firewall**, **API catalog** and the troubleshooting answer are laid out by one function (`plainText` in `webui/app.js`): a list of records is a table with a header, a record is `Name  value` lines, a nested part is indented, empty values are left out. **Configuration** and **Show** were text already. Copy and Download give the same text.

### Verified
- `node --check webui/app.js`; `plainText` run in node on a list of records, a nested record and an empty list; `gofmt -l .`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.

### Not verified
- Not opened in a browser (light or dark) and no jsdom run of the popup; no real device answer was formatted, only made-up ones, so a platform whose answer is deeply nested may still read long. Nothing else in the GUI changed.

## [v127] - 2026-11-10 — device_facts from the health monitor

### Added
- **A facts read can come from the health monitor.** The monitor already asks every device for its facts in the background (every 5 minutes while someone is looking). When an MCP caller asks `device_facts` and the monitor's copy is at most 5 minutes old and good, that copy is the answer: no login, no request, instant. The result says `"from_monitor": true` and `"cached_s"` (the age), and the uptime is advanced by the age. A copy that is older, a facts request that failed last time, a device that is down or paused, and a device the monitor has not asked yet are asked live, as before. `fresh: true` asks the device, as for every read; the GUI always asks the device; `NETDIR_DEVICE_CACHE=0` switches it off. On a replica the primary's copy is used.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -race -count=1 ./...`, no-cgo suite, `sh tools/leaktest.sh`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`.
- `TestFactsFromMonitor`: a recent good copy is the answer, with the uptime advanced and the monitor's own copy untouched; an old copy, a failed facts request, a down or paused device, a device never asked and no data at all are not.

### Not verified
- Not run against real devices, and the monitor's timing was not watched live; a facts read of a device the monitor does not watch (idle for hours) is asked live, since its copy can be six hours old.
- Only the unit test covers the route: the HTTP path was not driven with a seeded monitor.
- GUI: nothing changed; not opened.

## [v126] - 2026-11-10 — Short memory for repeated reads and for tshoot's lookups

### Added
- **Repeated reads come from memory.** An MCP caller that asks a device the same read again within 30 seconds gets the first answer again, with `"cached_s": N` (its age in seconds) on that device's result and no time spent (`answercache.go`, `device/cache.go`). The key is the device with its login, the question (op and path) and the caller's privilege (read-only or not), so another login, another path or a read-only key never shares an answer. Only what holds no secret and is no search is kept: `facts`, `interfaces`, `neighbors`, `neighbor_details`, `ports`, `routes`, `routing`, `firewall`, `resources`, `vlans`, `api_catalog` and `api` paths that do not name a log, a job or a capture. Never kept: `config` and `show` (secrets, and a CLI command may be anything), log searches, changes, a failed answer, a caller whose privacy level is none, and the GUI (it always asks the device). A device below a Network Director is not kept either.
- Every read tool has `fresh` (true: ask the devices again, nothing from memory); the HTTP route takes `fresh=1`.
- **tshoot: the Meraki network list is kept 5 minutes,** so a second run does not list the networks again.
- **tshoot: where a machine was found is kept 30 minutes.** A repeat for the same host name, MAC or account asks the networks it was found in first; when it is found there, only those were searched and the answer's `notes` say so (`searched the N network(s) it was seen in M minutes ago, not all K`), and `networks_searched` is the number asked. When it is not found there, every network is asked as before. A search with a named network never uses it.
- **tshoot: the Entra lookups are kept 90 seconds:** who a user is and the devices of the user, and a device name and its users. A failed lookup is not kept.
- The configuration being loaded empties all of it (a login or a device may have changed). `NETDIR_DEVICE_CACHE=0` in the daemon's environment switches it all off. What is returned from memory is a copy: a caller that changes an answer does not change the kept one.

### Changed
- `TestDeviceReadsShareOneSignIn` reads with `fresh`, or the second read would be from memory instead of over the kept driver.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64`, `sh tools/leaktest.sh`.
- `TestDeviceAnswerCache`: the first read asks the stub, the repeat does not and says `cached_s`, `fresh` asks again; which operations may be kept (a configuration, `show`, a log path and a job are not) and that the GUI, a raw caller and a fresh read never are.
- `TestEntraLookupsAreKept`: the repeat does not reach Graph, a caller's change to an answer does not reach the kept one, a flush asks again, a refused name is not kept.
- `TestMerakiClientMemory`: the list of networks is read once; the repeat of a search asks only the network the client was found in and says so; a wrong memory (the machine is no longer there) falls back to every network without claiming less; a named network ignores the memory.

### Not verified
- Not run against real devices; no time was measured. Lifetimes (30 s, 90 s, 5 min, 30 min) are guesses at what is safe: a read can be up to 30 seconds old, and a client that moved to another network within 30 minutes is not found by the short search when it is also still seen where it was (the first network answers, the others are not asked): ask with `fresh`-style certainty by naming no network and changing the host spelling, or switch the cache off. A machine that connects to two networks at once is reported only where it was found before.
- GUI: nothing changed; not opened.

## [v125] - 2026-11-10 — Reads keep their login; tshoot gets the Wi-Fi

### Added
- **Reads reuse the driver.** A read of a device used to cost a TLS handshake and, on most platforms, a login before the question and a logout after it. The driver a read used (its connections and its session or token) is now kept for the next read of the same device (`device/pool.go`, `FanoutReuse`): for two minutes without use and never longer than ten minutes, one request at a time per driver (two reads at once use two), at most two idle per device and 512 in all. Every `device_*` read (`/api/devices/query`) and `tshoot` use it. What the device answers is asked anew each time: nothing a device said is kept (the PAN-OS and Observium drivers, which remembered something for the length of a request, forget it before they are used again).
- An answer that came over a kept driver says `"reused": true`.
- A kept driver whose session the device has ended (401, 403) or whose connection has gone fails the first read it is used for; that read is then made once more with a new driver, so the caller sees no error. A driver that failed in any way is closed, not kept.
- Changes (`device_change`, `device_change_raw`), captures and the health check do not use it: each has a driver and a login of its own, as before.
- The kept drivers are closed, and their sessions logged out, when the configuration is loaded (a device or login may have changed; the key of a kept driver is everything it was opened with, the login included) and when the daemon stops.
- `NETDIR_DEVICE_REUSE=0` in the daemon's environment switches it off.
- **tshoot: the Wi-Fi.** A wireless client's `connection` now starts with `now` (SSID, AP, VLAN, address, the newest RSSI in dBm and SNR in dB) and has `signal_quality`, `data_rate` and `latency_history` over the window (only the intervals that have a value), beside the connection statistics, latency, connectivity events and failed connections it had.
- **tshoot user: the clients that signed in with the account.** Besides the machines Entra and the VPN log name, every Meraki client that signed in to the network as the user (802.1X; `CORP\jsmith`, `jsmith@…` and `jsmith` are one) is reported, as one more entry of `devices` with `found_by`: a phone on the Wi-Fi has a host name no directory knows. Their addresses go into the firewall log search too.

### Fixed
- tshoot searched only the first 60 Meraki networks, one after the other, and one network the dashboard failed on (a 502) ended the whole search with an error. It now asks every network that has an AP, a switch or an appliance (at most 400; camera, sensor and systems manager networks are skipped), five at a time, and a network that fails is named in `notes` while the others answer. In an organization with more than 60 networks a client beyond the first 60 was reported as not seen, and with it its Wi-Fi.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `sh tools/leaktest.sh`.
- The pool (`device/pool_test.go`, with the race detector): three reads are one login and no logout; a change has a driver of its own; another password or address is another driver; the idle time and the age limit, also for a driver in steady use; a 401 on a kept driver is asked again and the caller gets the answer, a 404 is the answer and the driver is closed; 40 reads at once never share a driver, none is lost, at most two stay; a driver that panics is closed; switched off, nothing is kept.
- `TestDeviceReadsShareOneSignIn`: against the Entra and Meraki stubs four troubleshootings and four MCP reads make one sign-in to Entra, the second MCP read says `reused`, and after the configuration is saved nothing is kept and the next read signs in again.
- `TestMerakiClientReport`: the signal history without its empty intervals, `now` with the newest reading, the data rate, a history the dashboard does not have said as unavailable; the camera network is not asked; the network that answers 502 is named and the others are searched; by the account (`CORP\jsmith`) the phone is found, and the laptop is left out when it is reported under its name. The troubleshooting tests have the phone as a third entry with its signal.

### Not verified
- No speed was measured: there is no real device in the sandbox. What is saved per read is one TLS handshake and one login (and a logout), which on a switch or a firewall is usually most of a short read; the tests count logins, not milliseconds.
- Not run against real devices. The risk of keeping sessions is on platforms that limit them (ArubaOS-CX allows a few sessions per user): netdir now holds up to two sessions per device for up to two idle minutes where it held one for the length of a read; the health check's own login comes on top, as before. If a platform objects, `NETDIR_DEVICE_REUSE=0` restores the old way.
- The connections of a kept driver still close after 30 seconds without use (unchanged), so a read after a longer pause saves the login but not the handshake.
- The Wi-Fi history paths (`/networks/{id}/wireless/signalQualityHistory`, `dataRateHistory`, `latencyHistory` with `clientId`, `timespan`, `autoResolution`) and the `user` and `productTypes` fields are Meraki's dashboard API as documented, seen only in the stub, like the rest of the client report. A part the dashboard refuses is shown as `unavailable` with its reason.
- Why the Wi-Fi was missing on your gateway was not seen (no access to that answer): the network limit and the single failing network are the two causes found in the code. If it is still missing, the `notes` and the `network` part of the answer say what was searched and found.
- GUI: nothing changed; not opened.

## [v124] - 2026-11-10 — tshoot user and tshoot host, with the firewall's logs; troubleshoot is tshoot

### Added
- `netdir tshoot host NAME [HOURS]` (`--troubleshoot-host NAME`, `GET /api/devices/troubleshoot?host=NAME`, `device_troubleshoot_user` with `host`): start from a machine. The VPN (GlobalProtect) log of the Panorama says which user last connected with it and from where, Entra says which users are registered on a device of that name; the answer's `last_user` is the newest VPN event's user, or the user registered on the Entra device when the log has none. The machine is then followed like a user's.
- `netdir tshoot user NAME [HOURS]` now also asks the firewall: the VPN log is searched for the account (`(srcuser contains 'msmith')`), which names the machine the user connected with and its addresses, so a user who is only on the VPN is found too and a machine Entra does not list is followed (at most 3 machines).
- Both add `firewall`: the newest 50 traffic and 20 threat log entries for the addresses found (the VPN address and the address the Meraki client had, at most 4; `(addr in 10.1.2.3) or …`), and `vpn`: the query, the newest event as `last` and the newest 20 events.
- `troubleshoot` is the same word as `tshoot`: `netdir troubleshoot user msmith`, `netdir troubleshoot host PC-123 12`. `tshoot NAME` without `user` is still a user.
- `panorama=NAME` (MCP: `panorama`) picks the device whose logs are searched when there are several; without it the Panorama of the inventory is used, else the one PAN-OS firewall.
- GUI: the form has a **Host** box beside **User** (one of the two), and the menu item, now **Troubleshoot user or host**, is also on a Panorama and a PAN-OS firewall.
- Drivers: `LogSearch` on PAN-OS (the log search of v121 as a list of entries) and `DeviceUsers` on Entra (`/devices?$filter=displayName eq '…'`, then each device's `registeredUsers` and `registeredOwners`).

### Changed
- None of the three systems is required any more. Each is asked when it is in the inventory and enabled; one that is missing, or fails, is left out and `notes` says why. A user with no Entra device in the inventory is an error only when there is no Panorama or firewall to ask instead. A system that is named (`entra=`, `panorama=`) and cannot be used is still an error.
- The answer keeps its shape (`user`, `devices` with `entra` and `network`, `notes`, `window_hours`) and gains `name` on each device, `host`, `last_user`, `vpn`, `firewall` and `panorama_device`. A user without devices in Entra no longer ends the lookup: the VPN log may still name a machine.
- The names that go into a log filter are checked first (letters, digits and `. _ -`): a host with a quote or a bracket is refused, and a user typed as a name with spaces or an object ID is searched in the logs by the account name Entra gave.
- `hours` bounds the Meraki part as before. The log entries are the newest ones whatever their age: the firewall's clock and time zone are its own, so no time is put into the filter.
- Usage text, the MCP tool's description, the help and the README say all this.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `app.js` and `help.js`, `sh tools/leaktest.sh`.
- The tests of v123 for the user lookup pass unchanged (same answers without a Panorama).
- New tests against one stub that is Entra, Meraki and a Panorama: `TestTroubleshootUserWithFirewallLogs` (the three searches the firewall got, the machine of the VPN log joined with the Entra device by name, a second machine only the VPN log knows, the addresses and the traffic entry), `TestTroubleshootHost` (last user from the VPN log; from Entra's registered users without a Panorama; an unknown host is an answer with notes; a user and a host together, a quote, a space, a filter typed as a host, a wrong `panorama=` are refused), `TestTroubleshootHostOverMCPReadOnly` (a read-only caller gets it, the public address of the VPN event is hidden), `TestTroubleshootNames`, more cases in `TestShortCommand`; in the drivers `TestEntraDeviceUsers` and `LogSearch` in `TestPANOSLogSearch`.
- Live CLI against a real daemon with a Panorama that refuses the connection: `netdir troubleshoot host pc-1`, `netdir tshoot user msmith 3` and `netdir tshoot msmith` answer with the query, the error of the search and the notes; a host with a quote is refused; the audit line is logged for each.

### Not verified
- Not run against a real Panorama, Entra or Meraki. The filters rest on PAN-OS's log field names as documented, not on a device: `srcuser` and `machinename` with `contains` in the GlobalProtect log, `addr in` in the traffic and threat logs, and `private_ip` as the VPN address of an entry. If your Panorama names one differently the search answers an error or nothing, `vpn.query` and `firewall.query` in the answer show exactly what was asked, and `device_api_get` with `type=log` takes any filter by hand.
- Entra: reading `/devices` and a device's registered users needs the application to be allowed to read devices and users (it already reads a user's devices; whether your registration covers this direction was not tried). A refusal is shown on the device as `registered_users_error`.
- `contains` matches part of a name: `joe` also finds `joey`. The account name is used whole, but a short one can match others; the events show the names found.
- The GUI form and menu were not opened in a browser (`node --check` only).
- Log entries name users and machines; masking for MCP callers is as for every answer (addresses, serial numbers; not names).

## [v123] - 2026-11-10 — Privacy: an e-mail address is shown by its name only

### Changed
- An e-mail address in an answer to an MCP caller is now the name before the `@` and nothing else: `jo.doe@example.com` is `jo.doe`. v122 wrote `jo.doe@MASKED-EMAIL-3fa91c`; the `@` and the token are gone. Nothing of the domain is shown and nothing stands in for it.
- So an answer no longer says that a name was an e-mail address, or which addresses share a domain. The `MASKED-EMAIL` token is no longer made.
- **E-mail addresses** on Configure ▸ Privacy, its default (on for standard and strict) and the setting are unchanged; with the box off an address is shown whole.
- The tool instructions an MCP caller reads, the help (MCP) and the README say so.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `help.js`.
- Test `TestMaskEmailShowsOnlyTheName` (it replaces v122's): three addresses in a sentence become their names as written, the text around them is untouched, and masking the result again changes nothing.
- `sh tools/leaktest.sh` passes: no whole e-mail address of the drivers' test data gets through the strict level.

### Not verified
- The name before the `@` reaches the caller by design; a name that is itself sensitive is shown unless it is a word of yours on Configure ▸ Privacy.
- A domain that appears on its own in an answer (a host name, a DNS zone) is not hidden by this box, as before.
- Not looked at through a live MCP caller.

## [v122] - 2026-11-10 — Privacy: an e-mail address keeps its name, only the domain is hidden

### Changed
- An e-mail address in an answer to an MCP caller is no longer replaced whole. The name before the `@` stays and the domain becomes the token: `jo.doe@example.com` is now `jo.doe@MASKED-EMAIL-3fa91c` (was `MASKED-EMAIL-3fa91c`). So an assistant can tell users apart and name them, without learning whose domain it is.
- The token is made from the domain alone (lower case), so every address of one domain carries the same token and another domain another. As before it is a keyed hash that changes at a restart and between nodes and cannot be turned back.
- This is what **E-mail addresses** on Configure ▸ Privacy does at both levels; the box, its default (on for standard and strict) and the setting are unchanged. With the box off an address is shown whole, as before.
- The tool instructions an MCP caller reads, the help (MCP) and the README say so.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `help.js`.
- New test `TestMaskEmailHidesOnlyTheDomain`: the name is kept as written (with its capitals, dots and `+tag`), two addresses of one domain get one token whatever the case of the domain, another domain another token, no part of a domain is left, and masking the result again changes nothing.
- `sh tools/leaktest.sh` passes: no whole e-mail address of the drivers' test data gets through the strict level.

### Not verified
- The name before the `@` now reaches the caller by design. The leak test looks for whole addresses (name, `@`, domain), so it says nothing about names; a name that is itself sensitive (a person's full name) is shown. A word of yours on Configure ▸ Privacy still hides it.
- A domain that also appears on its own in an answer (a host name, a DNS zone) is not hidden by this box: that was so before and is unchanged.
- Not looked at through a live MCP caller; the change is one function in `mcpmask.go`.

## [v121] - 2026-11-10 — PAN-OS and Panorama: search the logs

### Added
- `device_api_get` (the `api` read of a device, `op=api`) reads the logs of a PAN-OS firewall or a Panorama: `/api/?type=log&log-type=globalprotect&nlogs=50&query=(machinename%20eq%20'PC-1')`. Until now the driver took only `type=op` (show commands) and `type=config`, so an assistant asked "when did this machine last connect" had to answer that it could not search the logs.
- Parameters: `log-type` (traffic, threat, url, wildfire, data, config, system, hipmatch, globalprotect, userid, auth, tunnel, decryption, gtp, sctp, iptag, corr, corr-detail, corr-categ), `query` (the filter of the Monitor tab, one line, at most 2000 characters), `nlogs` (1 to 5000; PAN-OS gives 20 when it is left out), `skip` and `dir` (backward, the default, or forward). Anything else is refused before the device is asked.
- PAN-OS answers a log search with a job. The driver starts it, reads it until it has finished (every half second, for at most 90 seconds) and removes it, so the caller makes one read and gets the entries; nothing matched is an empty list. The job requests (`action=get`, `action=finish`, `job-id`) are not taken from a caller.
- Over MCP every log type is read but `config`: the entries of the configuration log carry the changed configuration, secrets included.
- `device_api_catalog` explains the log search and gives an example for a firewall and for a Panorama; the tool description of `device_api_get`, the README and the help say so too.

### Changed
- The admin's XML API role needs **Log** as well as Operational Requests and Configuration for this. Without it PAN-OS refuses the search and that refusal is the answer; show commands and configuration reads work as before.
- "Only GET is ever sent" still holds: the three requests of a search are GETs. The removal of the job is the one request that is not a pure read; it removes only the job the search itself made.

### Fixed
- `sh tools/leaktest.sh` failed before it checked anything: `TestUnimusFallsBackToV2` asked the driver for its own type, which under the leak test is the recording wrapper (it failed the same way in v116). The test now asks through `bareDriver`.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub).
- New tests against the TLS stub of the XML API (`TestPANOSLogSearch`, `TestPANOSLogSearchGivesUp`): the search reaches the device with the query decoded, the job is read until `FIN` and then removed, the entries come back; an empty result; a refusal by the device; fifteen paths that are refused without a request (no or unknown log type, bad numbers, the job requests, a key, a second log type, a control character, `type=report`, `type=export`); a job that never finishes gives "did not finish in time" and is still removed; the MCP gate allows the log types and refuses `config` and the job requests.
- `sh tools/leaktest.sh`: passes (1265 recorded answers, 31 platforms), with the log entries of the new test (addresses, a serial number) among them.

### Not verified
- Not run against a real firewall or Panorama. The requests and the shape of the answers (`<job>`, `<job><status>FIN`, `<log><logs><entry>`) are PAN-OS's documented XML API as only seen in the stub; the field names of a GlobalProtect entry in the test are examples.
- A Panorama searches the logs it holds (its log collectors); logs kept only on a firewall are asked of that firewall.
- Log entries name users and machines. The strict privacy level hides addresses, serial numbers and the like in them as in every answer (the leak test covers those); user and machine names are not something the leak test looks for.
- GUI unchanged apart from one sentence in the help; not opened in a browser.

## [v120] - 2026-11-10 — Download as CSV on Monitor ▸ MCP and Monitor ▸ Node; MCP first in the Monitor menu

### Added
- Monitor ▸ Node: the small download icon of the DNS Director in the corner of each chart (CPU, Memory, Disk, Network utilization), the Filesystems table, the Network interfaces table and the LLDP neighbors card. It saves that card's numbers as a CSV file (`netdir-<card>.csv`), built in the browser from what the page holds. A chart gives one row per sample for the picked range, times in UTC, with the busiest sample of each interval beside the average for CPU, disk I/O and network; a gap is an empty cell.
- Monitor ▸ MCP: the same icon on Calls per hour, Data returned per hour, By key, By source address, By tool, By device and Newest calls, for the picked time range. Sizes are in bytes and times in UTC. A table with no calls has no icon. The tiles have none: they are the totals of the tables.
- A text cell that starts with `=`, `+`, `-` or `@` is written with a leading apostrophe, so a key or device name cannot be read as a formula by a spreadsheet (as in the DNS Director).
- Help (Monitor ▸ Node, Monitor ▸ MCP): a "Download as CSV" paragraph each.

### Changed
- The Monitor menu starts MCP, Node, Devices; the rest is as it was (Gateways, Cluster, Anycast, Alerts, Capture, Log).
- Monitor ▸ Devices has no download: the page asks devices questions and shows their answers as text, and an answer already has its own Download button.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `app.js` and `help.js`.
- Headless Chromium against a real daemon with a real PAM login, light and dark: the menu order; on Node the six icons shown (no LLDP on the sandbox) and the CPU, Network, Filesystems and Network interfaces files downloaded and read (headers, one row per sample, empty cells for the gap before the daemon started); on MCP the two chart files. No script errors.
- The MCP tables with calls in them: the same page with `/api/mcpusage` answered by sample data (the sandbox has no MCP caller): all seven icons, and By key, By device, Newest calls and Calls per hour downloaded and read, including a key named `=claude, "desk"` (written `'=claude, ""desk""` in quotes).

### Not verified
- The LLDP neighbors download (no lldpd in the sandbox; the code is the DNS Director's). The cluster view of Monitor ▸ Node. Opening the files in Excel or LibreOffice.

## [v119] - 2026-11-10 — A BGP neighbor's address can be changed

### Changed
- Configure ▸ Anycast ▸ Neighbors: the address of a neighbor can be changed after it is added. The first column of a row is now a box like the others: type the new address and leave it. Until now the address was plain text and the only way was to remove the neighbor and add it again.
- The neighbor stays the same neighbor: its AS, description, password and multihop are kept, and one that was switched off stays off. The page sends the old address along (`was`) with `PUT /api/bgp`; it is used to carry the on/off state over and is never saved. A bad address or one another neighbor already has is refused and the old one comes back.
- Help (Configure ▸ Anycast) says so. From the command line the way is unchanged: remove the neighbor and add it with the new address.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `app.js` and `help.js`.
- New test `TestBGPNeighborAddressCanBeChanged`: the address changes, the neighbor stays switched off, the old address is in neither the answer nor the file, a neighbor added without `was` starts switched on, a duplicate or bad address is refused.
- Headless Chromium against a real daemon with a real PAM login (dark): set an AS, added neighbor 192.0.2.1, changed its address to 192.0.2.9 in the row: `GET /api/bgp` and the row show 192.0.2.9 and one neighbor; typing `nonsense` was refused and 192.0.2.9 came back. No script errors.

### Not verified
- FRR was not installed for this run, so no session was watched moving from the old address to the new one; `frr.conf` is written from the saved settings as before.
- The switched-off state carried over is covered by the Go test, not clicked in the browser. Light theme not looked at for this change (a text box replaced text in one column).

## [v118] - 2026-11-10 — Back up to the cluster nodes in one step

### Added
- Configure ▸ Backup ▸ Servers ▸ **Use the cluster nodes** (shown in a cluster) and `netdir --backup-cluster` (`POST /api/backup/cluster`). One press replaces doing this by hand on every node: each node makes itself a local account `netdirbackup` (no password, key only), a directory `backups` in its home, and an `authorized_keys` with the backup keys of all the nodes; every node is then added to the shared list of servers. No password is typed or kept.
- The keys are added as `restrict,command="internal-sftp"`: file transfer only, no shell command. The account has a real shell (`/bin/sh`) because many SSH servers start SFTP through the account's shell, and a `nologin` shell is what made "Ensure the remote shell produces no output" appear when this was set up by hand.
- It can be pressed again: an account, key or server that is already there is left alone. A node that does not answer is named in red beside the button (and by the CLI, which then exits 1); press again when it is back.
- `POST /api/backup/provision` is what a node sends the others (the keys to authorize); it goes through the cluster's signed relay and is refused for read-only users like every other change.
- Help (Configure ▸ Backup): a step-by-step for it. Usage text: `--backup-cluster`.

### Changed
- Nothing in the existing servers, Install key or restore. The list still holds at most 8 servers: in a larger cluster the first 8 nodes are added and the rest are reported.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, cross-compiles for `linux/amd64`, `arm64`, `arm`, `386`, `riscv64` (cgo off: the PAM stub), `node --check` on `app.js` and `help.js`.
- New tests (`backupcluster_test.go`): the account is made once (`useradd --password *`), the keys are written once with the SFTP-only options, modes 700/600, a second run changes nothing, a line that is no key is dropped, an account with uid 0 is refused, a `.ssh` that is a symbolic link is not followed, and no cluster is an error.
- Live, as root in the sandbox: a real `sshd`, two real daemons clustered on 127.0.0.1 and 127.0.0.2. `--backup-cluster` on the replica: the account was made with password field `*`, `.ssh` 700, `authorized_keys` 600 with both nodes' keys, `backups` 700; both nodes' `netdir.conf` got the two servers (the change went through the primary). `--backup-now` on both: each node's archive arrived in `~netdirbackup/backups` and `--backup-status` shows success on both servers. `ssh … id` with a node's key answers "This service allows sftp connections only".
- Headless Chromium against those daemons with a real PAM login, light and dark: removed a server row, pressed **Use the cluster nodes**, the row came back, both config files hold both servers, no red text, no script errors.

### Not verified
- The two daemons ran on one host, so they shared one `/etc` and one account: the second node found the account the first had made. Making the account on a separate machine through the relay was not run (the per-node mount namespace check of the Users page was not repeated for this).
- Only Ubuntu's OpenSSH and `useradd` were used. RHEL-family hosts (SELinux contexts on a new `~/.ssh`, `sshd` settings such as `AllowUsers`/`AllowGroups` that would keep `netdirbackup` out) were not tried; **Test** on the row says so if a node refuses the login.
- A node that is down during the run, and a cluster of more than 8 nodes, were only read in the code, not run.
- A node also backs up to itself (it is in the shared list); that copy is of no use if the node is lost.

## [v117] - 2026-11-10 — The Install key password box keeps its width when shown

### Fixed
- Configure ▸ Backup ▸ Servers ▸ Install key: clicking the eye beside the password made the box narrower (288 px to 261 px). The width was set by a rule for `input[type=password]` only, and the eye turns the box into `type=text`. The width is now set by where the box is, not by its type (`style.css`).

### Added
- Test `TestPasswordBoxKeepsItsSizeWhenRevealed`: fails for any rule in `style.css` that sizes a password box without also naming the text type.

### Verified
- The new test passes, and fails with the old rule put back. `gofmt -l .` prints nothing.
- Real daemon (PAM build, amd64) with a throwaway PAM user, headless Chromium, light and dark: the box is 288 px wide hidden, shown and hidden again; with the old stylesheet the same run measured 288, 261, 288. No script errors.
- PAM login over HTTPS: the group member got in; a wrong password and a valid user outside the group were refused with the same message.

### Not verified
- The owner asked for the change without the full process, so these were not run for this version: `go vet ./...`, `go test -race -count=1 ./...`, the `CGO_ENABLED=0` vet and tests, and the cross-compiles (`linux/amd64`, `arm64`, `arm`, `386`, `riscv64`). The change is one CSS rule and one new test file.
- The root login in the PAM check was answered by the lockout ("Too many failed attempts") after the two refusals before it, not by the generic message; it was not repeated on its own.
- Other password boxes were not measured. No other rule sizes only the password type, but a few size only `input[type=text]` (`.bgprow`, `.devask`, `table.policy`), which could change a box there when it is shown.

## [v116] - 2026-11-09 — Clear unused join codes

### Added
- `netdir --cluster-token-clear` and **Clear join codes** on Operate ▸ Cluster (`POST /api/cluster/token/clear`): withdraws every join code this node has handed out that nobody used. A code created before no longer works. A node keeps at most 20 unused codes for an hour each, and until now the only way out of "too many" was to wait.
- The button is greyed out when there are none and its tooltip says how many there are (`join_codes` in the cluster status). Clearing also takes the code shown on the page away.

### Changed
- The refusal at 20 says what to do: `20 unused join codes: clear them (Operate ▸ Cluster ▸ Clear join codes, or netdir --cluster-token-clear) or wait for them to expire` (was "too many unused join tokens; wait for them to expire").

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`, `node --check` on `app.js` and `help.js`.
- New test `TestClearJoinCodes`: 20 codes, the 21st refused with the new text, the status counts 20, the op clears 20, a cleared code no longer joins, clearing none is no error, and a new code joins. The new route is in the lists the auth and CSRF tests walk.
- Headless Chromium against the real `webui/` with the API mocked (scratchpad, not in the tree), light and dark: at 20 codes the button is enabled ("20 unused") and Create join code shows the refusal; Clear join codes asks, posts, and is then greyed ("No unused join codes"); a new code can be created and the button counts it.

### Not verified
- Against a running daemon: the CLI flag was not run against a live socket and the GUI was driven with mocked API answers.
- The clearing is per node: the codes of another member are cleared on that member (pick it in the Node menu). Not tried on a real cluster.

## [v115] - 2026-11-09 — MCP on a gateway's right-click menu

### Added
- Topology: right-click a gateway ▸ **MCP** opens Configure ▸ MCP. The item is on the circle's menu (after Edit) and on the gateway's entry in the sidebar (between Rename and Delete).
- Help (Topology ▸ The sidebar) mentions it.

### Verified
- `node --check` on `app.js` and `help.js`; `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...` (with PAM, amd64), and `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`.
- Headless Chromium against the real `webui/` with the API mocked (scratchpad, not in the tree), one gateway: right-clicked the gateway in the sidebar (menu: Rename, MCP, Delete) and the circle on the drawing (Edit, MCP, Add device, …), chose MCP each time, and the page changed to Configure ▸ MCP (`#cfg_mcp`, MCP marked in the sidebar). No script errors.

### Not verified
- Against a running daemon: the API answers were mocked. Light theme only.

## [v114] - 2026-11-09 — MCP keys table fits

### Fixed
- Configure ▸ MCP ▸ Keys: with the new Expires column the fixed column widths were wider than the box, which pushed the Key column out and made the table scroll sideways. The columns are narrower (name, access, privacy, devices, added, expires) and the key takes what is left.

### Not verified
- Looked at in no browser: the widths were worked out from the stylesheet and the screenshot, not rendered here.

## [v113] - 2026-11-09 — Expiry for MCP keys and allowed sources

### Added
- **Expires (UTC)** on every MCP key (Configure ▸ MCP ▸ Keys, a column; empty is never) and on every allowed source (Configure ▸ MCP ▸ Allowed sources). From that time a key is refused with "this key has expired" and a source allows nothing; the row stays in the list, greyed, until it is deleted or given a new time.
- Written `2026-12-31` (the end of that day), `2026-12-31 17:00` or `2026-12-31T17:00Z`, always UTC. In the configuration file: `"expires": <unix time>` on a key; `until=2026-12-31T17:00Z` in an access-list entry (`10.1.1.50 rw until=2026-12-31T17:00Z`).
- An entry with an expiry is not merged with the others of its address (like a disabled one).

### Verified
- Tests: a key before and after its time (200, then 401, still listed), a source before and after its end, normalising and bad times, an access-list entry that has just ended changes the answer at once (not after the minute the host-name cache lasts).

### Not verified
- The GUI columns were not looked at in a browser; only the script syntax and the tests were run.

## [v112] - 2026-11-09 — Privacy none means none

### Changed
- A caller whose privacy level is **none** (its key's, its source's, or the default) now gets what a **device** answers as the device has it: `device_config`, `device_show` (including `show backup` on Unimus), `device_api_get` and the other device tools no longer have secrets removed (passwords, hashes, SNMP communities, keys). Before, **none** hid addresses no more but the secret filter still ran.
- Not changed at none: netdir's own settings (`get_config`, `api_get`, `list_devices`): device logins, MCP keys and tokens stay hidden. The login netdir uses to reach a device is still kept out of answers by leak capture.
- Every such answer is logged (`mcp: KEY was given device_config unfiltered (privacy none)`).
- Standard and strict are as before.

### Implementation
- `device.RunRaw` marks the goroutine that runs the request, and `Redact`, `RedactText`, `RedactConfig`, `RedactConfigValue` and the DNS filter leave the answer alone while it runs (`device/rawsecrets.go`). A goroutine a driver starts itself is not marked, so what it reads is still filtered: on the safe side.

### Verified
- Tests: the filters under and outside the mark, another goroutine, `show backup` raw, and through MCP: `device_config` at none shows the hash, at standard not, `get_config` and `list_devices` never show a device login.

### Not verified
- Not every driver was run raw against a real device; drivers that read in goroutines of their own may still filter part of an answer.

## [v111] - 2026-11-09 — Unimus: names that are a host name's first label

### Fixed
- `show backup nphxdcswi101` finds a device whose Unimus address is `nphxdcswi101-m.net.axway.int` (the first label of the address or name, with or without `-m` or `-new`), as the import names devices.
- On v2, when the backup record holds no text, the single backup (`/devices/<id>/backups/<backup id>`) is read; the text is looked for under `bytes`, `content`, `text` and `config`.
- When there is still no text the error lists the field names of the record (not their values), so the right one can be added.

## [v110] - 2026-11-09 — Unimus v2: the numeric ID

### Fixed
- On API v2 a device row can hold both `id` (776) and `uuid`; the driver put the `uuid` in the path and Unimus answered 400 "Argument deviceId type mismatch" for every backup read, whatever the device was called. v2 paths now use the numeric `id`, v3 the `uuid`.
- When both backup paths on v2 fail, the error names both requests and what each answered (the fallback hid its own error before) and the fallback no longer sends paging parameters.

## [v109] - 2026-11-09 — Unimus v2: backup list form, catalog

### Fixed
- `device_api_catalog` listed the v3 path `/devices/backups?deviceUuids=…` on a server speaking v2, where Unimus read `backups` as a device ID (HTTP 400 "Argument deviceId type mismatch"). The catalog now lists the paths of the version the server speaks.
- On v2, a 4xx from `/devices/<id>/backups/latest` falls back to `/devices/<id>/backups?latest=true` (the form seen working on Unimus 2.9.1).

## [v108] - 2026-11-09 — Unimus: read a backup by name

### Added
- **`show backup <name|address|id>`** on the Unimus server device: the text of the latest backup of that device, filtered like any configuration (secrets hidden). Before, the text was reachable only through a second device entry with the option `device`, so an MCP client asking the server device for "the backup of nphxdcswi101" got metadata only.
- Devices are found by address, by the name Unimus shows (exact, or the one device whose name starts with it) or by ID.

### Changed
- `show backups device=<name|address|id>` takes a name too; on API v2 it lists the backups of that device (`/devices/<id>/backups`).

## [v107] - 2026-11-09 — Unimus: older releases

### Fixed
- **`unimus`** answered HTTP 404 ("URL is not supported by the API") on a Unimus before 2.2, which has no `/api/v3`. Without the option `api_version` the driver now tries `/api/v3/health`, and on a 404 uses `/api/v2` (the choice is kept for the connection). `api_version=v2` or `v3` still forces one.

### Verified
- A stub server that answers only `/api/v2` (data wrapper, `paging`, numeric IDs, `findByAddress`, `backups/latest`): facts, show, config and import rows.

### Not verified
- Not run against a real Unimus; the v2 field names (`vendor`, `type`, `bytes`) are from its documentation.

## [v106] - 2026-11-09 — Unimus

### Added
- **`unimus`** (Unimus configuration backup, REST API v3, v2 by option): facts, `show`, `device_api_get`/`device_api_catalog`, changes with `device_change_raw` (guarded: no push, credentials, connections, backup uploads or deletes). With the option `device` the configuration is that device's latest backup (filtered over MCP).
- **Import ▸ Devices** from a Unimus server: platform picked from vendor, type and model, disabled, tagged `source=unimus`.
- GUI: platform label, import menu, help; README section.

### Verified
- Tests with a stub server: health and counts, paging, address lookup, latest backup decoded and filtered, API reads that name credentials refused, the backup text kept out of API answers, the change guard, import, platform mapping.

### Not verified
- Not run against a real Unimus; the v3 API is a draft and field names come from its OpenAPI file.

## [v105] - 2026-11-08 — Copy ▸ To all gateways

### Added
- **Right-click a gateway ▸ Copy ▸ To all gateways:** adds the devices of this gateway that another gateway lacks to every other gateway, after a confirmation that lists how many each gateway gets. Nothing is removed; run it again after changing the source. It is greyed out, with the reason, when the gateway has no devices, there is no other gateway, or every other gateway has them all.

### Changed
- **Copy all devices** moved into the same menu as **Copy ▸ All devices** (it fills the clipboard that **Paste N devices** uses, as before).

### Not verified
- The menu was not looked at in a browser; only the script syntax and the tests were run.

## [v104] - 2026-11-08 — Cisco IOS, Catalyst SD-WAN, NSX-T and ACI

### Added
- **`ios`** (classic Cisco IOS, SNMP v2c and v3, read only): facts, interfaces, ports, LLDP and CDP neighbors, routes, `show oid`, `/oid/…`. A minimal SNMP client in the standard library (`device/snmp.go`): BER, GET and GETBULK, USM with MD5 and SHA-1/2 authentication and AES-128 or DES privacy, time-window and engine-ID resynchronisation. No configuration (SNMP cannot hand it over) and no SSH (none exists in the standard library).
- **`sdwan`** (Catalyst SD-WAN Manager), **`nsxt`** (NSX Manager) and **`aci`** (APIC): facts, `show`, `device_api_get` and `device_api_catalog`, changes with `device_change_raw` (guarded, no accounts, keys, certificates, upgrades or restarts); ACI also interfaces, LLDP and CDP neighbors and the tenants' configuration.
- GUI: the four platforms in the device list (default port 161 for `ios`), help and README sections.

### Changed
- Observium's OS `ios` and IP Fabric's Cisco IOS (not IOS-XE) are imported as `ios`, no longer as `iosxe`.

### Verified
- Tests: the RFC 3414 key-localization examples; BER round trips; an SNMP agent in the tests serving v2c and v3 (authNoPriv SHA, authPriv SHA-256/AES, MD5/DES, SHA-512/AES); the three REST drivers against TLS stubs (login, expiry and renewal, logout, reads, refusals of accounts, keys and certificates, changes and refused changes).

### Not verified
- None of the four has run against a real device. The OIDs, paths, class names and fields are from the standards and the vendors' documentation. SNMPv3 against a real IOS agent (the stub is written from the same RFCs as the client) is the most likely to need a fix.
- An unattended SNMP read of a large switch is many UDP requests (a walk of 25 rows at a time).
- Not done: SNMP over IPv6 was not tried, SSH and telnet CLI, SD-WAN per-device interfaces and neighbors, NSX interfaces, import from these platforms.

## [v103] - 2026-11-08 — version bump only

No code change since v102.

## [v102] - 2026-11-08 — hidden values are written with x

### Changed
- **IP addresses** hidden from an MCP caller are written with an `x` for each hidden part instead of a token: `x.x.x.x`, `203.0.x.x`, `x.x.114.7`; IPv6 the same, with the longest run of shown zero groups as `::` (`x:x:x:x:x:x:0:8888`).
- **MAC addresses**: `xx:xx:xx:3c:4d:5e` (NIC part shown), `00:1a:2b:xx:xx:xx` (OUI part shown), `xx:xx:xx:xx:xx:xx` (hidden), in the notation the address was written in.
- **AS numbers** show their last three digits (`xx169`, `AS` kept: `ASxx169`); **route distinguishers** (a key named rd or route-distinguisher, or `rd A:B` in a command) hide their AS number or address as the rules say and show the last three digits of the number after it (`xx000:x00`).
- E-mail addresses, serial numbers, ids and your own words are still hashed tokens (`MASKED-EMAIL-3fa91c`).
- A value written with x, sent back in a change, is restored from the configuration like the old tokens (a real value without an x is never taken for one).
- The privacy form's labels show the new forms. README, help and the MCP instructions are updated.
- The refusals of whole-configuration paths and `show config` name `device_config` (v101).

### Fixed
- Two addresses used as keys of one JSON object that now read alike (`x.x.x.x`) stay two keys (the second is `x.x.x.x#2`).

### Not verified
- Two addresses that differ only in hidden parts can no longer be told apart by the assistant; that is the price of the shorter form.
- Route distinguishers are found by key name and by `rd` in text, not wherever an `A:B` stands.

## [v101] - 2026-11-08 — refusals name device_config

### Changed
- The refusals of `fullconfigs`, `running-config`, `startup-config`, `show config` and a whole-configuration path, and the "this platform runs no CLI commands" error, now say to use `device_config` (secrets hidden), so a client that is refused knows where to go.

### Not verified
- An MCP client that still reports no such tool is talking to an older build or holds a cached tool list: check Monitor ▸ About for the version on every node it can reach, and reconnect the client.

## [v100] - 2026-11-08 — config filter checked against every platform's format; shorter MAC label

### Changed
- Privacy ▸ MAC addresses: the option reads "NIC part shown (…:3c:4d:5e)".
- The configuration filter was run over a sample in each platform's own format (IOS-XE JSON, NX-OS, EOS, FortiOS, PAN-OS XML, Junos) and leaked in five places; all are fixed:
  - SNMP community names in a JSON configuration (IOS-XE `snmp-server` ▸ `community`, `community-or-user` of a host): every key naming a community under an SNMP key is hidden (a BGP community elsewhere is not).
  - `snmp-server host … version 2c COMMUNITY` (NX-OS, EOS, IOS): the community is hidden.
  - `snmp-server user … auth sha KEY priv aes KEY` (EOS): both keys are hidden.
  - FortiOS `config system snmp community`: the `set name` of each community is hidden.
  - PAN-OS XML (one line or many): the text of every element, and the value of every attribute, with a secret's name (`phash`, `secret`, `key`, `snmp-community-string`, ...) is hidden and the rest of the XML kept. Before, the first secret word hid the rest of the line, so a one-line answer showed what came before it.

### Verified
- `TestConfigFilterEveryPlatform`: invented configurations in the six formats lose every listed secret, keep their readable parts and filter the same way twice.

### Not verified
- The samples are written from memory of each platform's syntax, not taken from real devices. Junos still hides a `community NAME {` line whole, so its brace is lost. A secret under a name on no list still passes.

## [v99] - 2026-11-08 — a device's running configuration over MCP, secrets hidden

### Added
- **`device_config`** MCP tool: the running configuration of each device picked. Every answer goes through the shared secret filter (key names, text lines, certificates, the list under Configure ▸ Privacy ▸ Secret words); `device.RedactConfig` / `RedactConfigValue`. JSON configurations (ArubaOS-CX) stay valid JSON.

### Changed
- `GET /api/devices/query?op=config` is answered to MCP callers (read-only or read-write), filtered; it is still refused to a read-only GUI account. Answers relayed from a gateway below are filtered again here.
- README, help and the MCP instructions no longer say the configuration is never offered. The generic `device_api_get` still refuses `fullconfigs`, `running-config` and `startup-config`.

### Verified
- Tests: stub IOS-XE switch answers `device_config` and `api_get op=config` with its secret hidden to read-only and read-write callers; JSON stays valid and filtering is idempotent.

### Not verified
- A secret kept under a name that is on no list (built in or yours) is not recognised: add such words under Privacy ▸ Secret words. Never run against a real ArubaOS-CX switch; the field names in the tests are my reading of the schema.
- The GUI read-only refusal of `op=config` has no new test.

## [v98] - 2026-11-08 — one list of secret words; more built-in ones; JSON no longer broken

### Added
- **Configure ▸ Privacy ▸ Secret words** (`settings.privacy.secret_words`): words of your own that mark a secret. One list for every filter: a key name that holds one has its value hidden, a line or a JSON member is hidden from that word on, and a path, XPath or command word that holds one is refused. Applies at every level, `none` included.
- Built-in secret words: `passkey`, `auth_pass`, `priv_pass`, `authentication_key`, `keepalive_key`, `ciphertext`, `keystring`, `shared_key` (and their `-` forms). RADIUS and TACACS+ keys, SNMPv3 passwords, OSPF and MC-LAG keys of an ArubaOS-CX configuration were not hidden before.
- A list of texts that is a public key (`ssh-rsa …`), or holds a secret word, is hidden whole.

### Fixed
- **The text filter broke JSON.** A line that opens an object (`"SNMP_Community": {`) was cut at the secret word, and a value already hidden (a certificate) was cut again (`"(hidden: key (hidden)"`). Both stay valid JSON now. An object or list named `snmp…community` is hidden whole, since its keys are the community names.

### Verified
- `TestConfigFilterHidesSecrets` (a representative AOS-CX running config: nothing secret left, still JSON, hostname and addresses kept), `TestSecretWordsOfYourOwn`, `TestNormPrivacySecretWords`; the full checklist.

### Not verified
- The AOS-CX field names in that test are my reading of its schema, not a real `fullconfigs` dump. A secret under a name nobody listed gets through: add the word.
- A device's configuration is still not offered over MCP (`config` is refused, and so is the `fullconfigs` path). This release makes the filters safer; it does not open that.
- The Privacy page's new box has not been looked at in a browser.

## [v97] - 2026-11-08 — the checkbox is called Enable

### Changed
- The checkbox under the list in *Add ▸ Devices of the inventory* is labelled **Enable**, not "Enable them …".

## [v96] - 2026-11-08 — Add device: an Enable checkbox

### Added
- *Add ▸ Devices of the inventory* has a checkbox under the list, **Enable**: ticked, the devices picked are enabled as they are added (imported devices come in disabled). Unticked (the default) leaves each as it is. *＋ new device* is still what the dialog opens on.

### Verified
- `node --check` only; nothing in Go changed.

### Not verified
- Not looked at in the running app.

## [v95] - 2026-11-08 — Add device: a plain choice, then the list

### Changed
- **Add device on a gateway is two steps again, not one tall list beside the new-device fields.** *Add* is a short choice: *＋ new device* (the form as before) or *Devices of the inventory*, which hides the new-device fields and shows one full-width list where Shift-click and Ctrl-click pick several. v92 put the list and the fields together, which looked wrong.

### Verified
- `node --check` only; nothing in Go changed.

### Not verified
- Not looked at in a browser.

## [v94] - 2026-11-08 — topology: remove or delete the picked devices

### Added
- With several devices picked on the map, right-click ▸ **Remove from this gateway** (they stay in the inventory) and **Delete devices** (out of the inventory and every gateway, after a confirmation). The Delete key takes every picked device off the gateway.

### Verified
- `node --check` of `app.js` only; nothing in Go changed.

### Not verified
- Not looked at in a browser.

## [v93] - 2026-11-08 — topology: pick several devices

### Added
- **On the topology map, Shift-click picks a run of devices and Ctrl-click (Cmd-click) adds or removes one.** Right-click one of the picked devices: **Enable**, **Disable** or **Copy devices** for all of them at once (then **Paste N devices** on another gateway). A plain click, a click on the empty drawing, or a right-click on a device that is not picked goes back to one.

### Verified
- `node --check` of `app.js` and `help.js` only; nothing in Go changed.

### Not verified
- Not looked at in a browser. Delete and drag still act on the one device last clicked, not on the picked set.

## [v92] - 2026-11-08 — Add device: pick several at once

### Changed
- **Add device on a gateway:** the Device list is now a multi-select. Shift-click or Ctrl-click picks several inventory devices and all are added to the gateway (ones already on it are left out). *＋ new device* still stands alone: picking it with others is refused.

### Verified
- `node --check` of `app.js` and `help.js` only; the Go tests were not run for this change (nothing in Go changed).

### Not verified
- Not looked at in a browser: the list's height and the new-device fields hiding and showing as the selection changes.

## [v91] - 2026-11-08 — version bump

### Changed
- No code change from v90. The version moves so a tree updated over v86–v89 can be told apart from one that still holds the old `device/obsimport.go` and `device/obsimport_test.go`: those two files were replaced by `device/import.go` and `device/import_test.go` in v87, and unpacking a tarball over an old tree does not delete them. If a build fails with `obsPlatforms redeclared`, delete the two old files.

### Verified
- The full checklist, unchanged.

## [v90] - 2026-11-08 — import from Proxmox Datacenter Manager and Aruba Fabric Composer

### Added
- **Import Devices from a Proxmox Datacenter Manager:** the nodes of each remote it manages, a Proxmox VE remote's as `proxmox` and a Backup Server remote's as `pbs`, disabled, with no login, tagged `source=pdm` and `remote=ID`. A node listed by IP address is named `ID-N`.
- **Import Devices from an Aruba Fabric Composer:** its switches as `aoscx`, tagged `source=afc` and `fabric=NAME`, by management address (else the switch name).

### Changed
- The GUI menu is **Import ▸ Devices** and **Import ▸ Preview** (one submenu) on every import source.

### Verified
- `TestImportFromPDMAndAFC` (names, platforms, tags, the AFC stub); the full checklist.

### Not verified
- Not run against a real PDM or AFC. PDM's `/remotes/remote` is assumed to list each remote's `nodes` with a `hostname` (the test stub lists none); a PDM that does otherwise falls back to the remote's own `server`/`host`, or skips. AFC's switch fields (`ip_address`, `name`, `fabric_name`) are my reading of its API Explorer, not checked: a switch without an address is imported by its name, so it must resolve in DNS.
- The Proxmox `node` option is not set on imported hosts.

## [v89] - 2026-11-08 — import from Panorama; copy all devices of a gateway

### Added
- **Import Devices from a Panorama:** the firewalls it manages (`show devices all`) are added as `panos` devices, disabled and with no login, tagged `source=panorama` and `dg=DEVICE_GROUP`, named by host name (the same rules as the other imports; one already there is skipped).
- **Right-click a gateway ▸ Copy all devices,** then **Paste N devices** on another gateway (circle or empty drawing). Paste leaves out the ones already there and any no longer in the inventory. **Copy device** still copies one.

### Verified
- `TestImportFromPanorama` (against the Panorama stub); the full checklist.

### Not verified
- Not run against a real Panorama: the shape of `show devices all` is the one in the driver's test stub. A Panorama that names the fields otherwise would skip devices as having no address.
- The copy and paste menu has not been looked at in a browser.

## [v88] - 2026-11-08 — import: Infoblox and Proxmox, shorter names, existing devices skipped

### Changed
- Observium's OS `infoblox` imports as `nios` and `pve` (and `proxmox`) as `proxmox`.
- The inventory name is the first label of the host name, without a trailing `-m` or `-new` (`aptxipm02-m.net.axway.int` becomes `aptxipm02`).
- A device whose name is already in the inventory is **skipped** ("already in the inventory (same name …)"), as one with the same address already was. Before, it was imported as `NAME-2`. Two hosts that shorten to the same name (`x` and `x-m`) import once, the first.

### Verified
- `TestObserviumImportRows` now covers the new OS names, the suffixes and the same-name skip; the full checklist.

### Not verified
- Not run against your Observium: the OS names `infoblox` and `pve` are the ones from your list.

## [v87] - 2026-11-08 — import devices from IP Fabric and Centreon too

### Added
- **Import Devices works from IP Fabric and Centreon as well as Observium** (same right-click item, `netdir --device-import`, `POST /api/devices/import`). Devices are added disabled, with no login, tagged `source=ipfabric|centreon`; IP Fabric adds `site=` from its site name, Centreon `poller=` from the monitoring server. The driver comes from IP Fabric's vendor/family/platform, or from the names of a Centreon host's templates, categories and groups; one that does not say is skipped with the reason.

### Changed
- The import code is one path (`device/import.go`) for the three sources; the Observium behaviour of v86 is unchanged.

### Verified
- `TestImportPlatformGuesses`, `TestImportFromIPFabricAndCentreon` (against the IP Fabric and Centreon stubs), the v86 Observium tests; the full checklist.

### Not verified
- Not run against a real IP Fabric or Centreon. The platform guesses (IP Fabric's vendor and family strings, Centreon's plugin-pack template names such as `Net-Cisco-Standard-SNMP`) are from memory, not checked; a wrong guess skips a device, it does not import it under the wrong driver, except that a Cisco template cannot tell IOS-XE from classic IOS or Nexus-style names it does not know.
- The Centreon stub has no `/configuration/hosts`, so the template read is exercised only as "refused": every stub host is skipped.
- IP Fabric's address is the `loginIpv4` column (else the host name); a release that names it otherwise falls back to the host name.
- The GUI menu items for IP Fabric and Centreon have not been looked at in a browser.

## [v86] - 2026-11-08 — import devices from Observium

### Added
- **Import the devices an Observium server monitors.** Right-click the Observium device ▸ **Import devices** (or **Preview import**), `netdir --device-import SERVER [--dry-run]`, `POST /api/devices/import`. Each device whose Observium OS has a driver here (ios, iosxe, nxos, eos, junos, fortigate, panos, aoscx, bigip) and that is not already in the inventory (same name or address) is added **disabled, with no login**, tagged `source=observium` and `site=LOCATION`. The name is the short sysName (made unique with `-2`, `-3`); the address is the host name, else the IP. Others are listed as skipped with the reason. Saved in the configuration history as the caller.
- Not an MCP tool, and refused over MCP like every other change to netdir.

### Changed
- A disabled device may have no login (it is never contacted). Enabling one without a login is refused when saved: "give it a login before enabling it".

### Verified
- `TestObserviumImportRows` (mapping, names, duplicates, location tag, skips, validity), `TestObserviumImportFromTheServer` (against the Observium stub), `TestDeviceImportRefusals`; the full checklist.

### Not verified
- The OS names Observium uses (`os`) are from memory of its OS list, not checked against a running Observium: an OS I have wrong is skipped as "no driver", not mis-imported. Tell me what yours report.
- Not run against a real Observium; the GUI menu items have not been looked at in a browser.
- Imported devices are not placed on a gateway; they appear in Configure ▸ Devices.

## [v85] - 2026-11-08 — MCP cannot change netdir; gateways in the Devices field

### Changed (breaking)
- **MCP can no longer change netdir's own configuration.** `rw` used to mean "anything the GUI can do"; it now means "change devices". Removed: `edit_config`, `api_request`, `set_node_paused`, `set_paused`, `alert_action`, `schedule_set`, `schedule_delete`, `schedule_run`, `update_fetch`, `update_apply`, `update_push`, `update_cancel`, `rename_node`, `set_label`, `set_gateway_node`, `set_gateway_device` and `clear_left_nodes`. Settings, cluster, gateways, nodes, schedules, updates, alerts, users and certificates are changed in the GUI only, so a client cannot damage the gateway.
- The rule is also in the request path (`mcpWriteGuard`): over MCP every request that is not a GET is refused except `POST /api/devices/change`, `/raw` and `/capture`, also through `api_get` and the node relay. A tool added later cannot slip through.
- Still there, read only: `get_config` (secrets hidden), `list_api`, `api_get`, and every monitoring tool. `device_change`, `device_change_raw`, `device_capture` stay for `rw`.

### Added
- **Gateways in the Devices field (keys and allowed sources).** A `gateway:N` pill (shown by the gateway's name in the GUI; type the name or `gateway:3`) gives the gateway and every device on it, now and later. A caller with only device entries sees no gateway. With a key and a source, both must name it. The access (ro/rw) is whatever the key or source has.
- A limited caller's `get_topology` and `get_gateways` show only its gateways; `get_alerts` drops the alerts about gateways and devices it may not see.

### Verified
- `TestMCPWriteGuard`, `TestGatewayScope`, `TestMCPGatewaysFollowTheScope`; the tests that used `edit_config` now change the configuration through the GUI path (`guiEditConfig`); the full checklist.

### Not verified
- The gateway pill and its name display have not been looked at in a browser.
- The alert filter (`scopeAlerts`) has no test of its own; `get_gateways` is tested only for what it must not show (a test cluster reports no gateways).
- Federation, and the log (`get_log`), are not filtered by gateway.
- The helpers that put `(hidden)` secrets back (`mcpRestoreHidden` and friends) are no longer reached from MCP; they are left in place and tested.

## [v84] - 2026-11-08 — MCP: limit a key or an allowed source to some devices

### Added
- **A Devices field on every MCP key and allowed source (Configure ▸ MCP).** Pills for device names and `tag:TAG`, and two special ones: **all** (the default, so nothing changes for what you have) and **none**. In the file: `"devices": ["sw1","tag:site=dc1"]` on a key, `10.0.0.20 rw devices=sw1,tag:site=dc1` on a source.
- A caller with both a key and a source may use only what both allow, as with the privacy level; a narrow key is not widened by its address.
- Outside its list a device is not in `list_devices` and is refused as if it did not exist. `all` and tags reach the devices the caller may use. A change or a capture that picks even one device it may not use is refused whole. Devices below a Network Director are limited the same way.
- A limited caller is not offered `get_config`, `edit_config`, `api_request`, `set_gateway_device` or `device_troubleshoot_user`, and the configuration, versions and sign-in routes are refused to it (also through `api_get` and the node relay): they hold every device and every key.

### Fixed
- **Right-click ▸ Disable on a key was lost when the page saved** (v81): the Keys table left the `disabled` flag out of what it saved. It is kept now.

### Verified
- `TestNormDevices`, `TestMCPACLDevices`, `TestSourceDevicesAndScope`, `TestMCPKeyLimitedToDevices` (list, targets, tags, names refused, changes refused whole, tools hidden, config routes refused, key and source together); the full checklist.

### Not verified
- The pill picker has not been looked at in a browser.
- `get_topology`, `get_alerts` and the log are not filtered by device: a limited caller can still see device names there.

## [v83] - 2026-11-08 — privacy: an address written as one decimal number is hidden

### Fixed
- **An IPv4 address written as a single number (`3232236805` for 192.168.5.5) was not hidden.** It is now, by the same rules as the dotted form, where something says it is an address: in JSON under a key that names one (`ip`, `addr`, `address`, `gateway`, `host`, `src`, `dst`, `hop`, `via`, `peer`, `neighbor`, also inside longer names such as `gw_addr`), as a number or as a string, and in text after such a word (`ip=3232236805`, `next hop 167772161`).

### Changed
- A number of 8 to 10 digits with no such word near it (a count of bytes, a time) is left alone, because it is far more often that than an address. So a decimal address with no label still gets through.

### Verified
- `TestMaskOddForms` (extended), `TestMaskDecimalAddressInJSON`, including counters and times that must stay.

## [v82] - 2026-11-08 — privacy: more ways of writing an address or a MAC are hidden

### Fixed
- **A MAC address written after a label was not hidden.** `MAC:BC:24:11:3D:2D:D8` and `hwaddr-bc-24-11-3d-2d-d8` were skipped, because the colon or dash in front made the masker take the address for a piece of a longer one. A word in front ("mac", "hwaddr") now ends the address; a run of up to four hex digits ("dead:") still counts as a piece of an IPv6 address.
- **A MAC in Cisco's `bc2411.3d2dd8` form, or written as twelve hex digits (`bc24113d2dd8`), was not hidden.** Both are now, at every setting (show, oui, nic, hide). A twelve-digit number made of digits only is left alone: it is far more likely a counter or a time.
- **An IPv4 address with leading zeros (`192.168.005.005`) or in hex (`0xc0a80505`) was not hidden.** Both now are, by the same rules as `192.168.5.5`.

### Verified
- `TestMaskOddForms`, including text that must stay as it is (a long count, a hash, an IPv6 address, a time).

### Not verified
- An address written as one decimal number (`3232236805`) is still not hidden: a number that size is as often a counter. Whether this was why pbs1's MAC showed is not known; I could not reproduce it with a real Proxmox answer.

## [v81] - 2026-11-08 — MCP: switch an allowed source or a key off and on

### Added
- **Right-click ▸ Disable / Enable on a row of Configure ▸ MCP ▸ Allowed sources and on a key.** A disabled entry stays in the list (greyed out) and allows nothing: a disabled address is skipped when the access is worked out, and a disabled key is refused with 401. Enable switches it on again. In the saved list an address reads `10.1.1.50 rw strict disabled`; a key has `"disabled": true`.

### Verified
- `TestMCPACLDisabledEntries` and `TestMCPKeyDisabled`; the full checklist (gofmt, vet, tests, CGO off, node --check, leak test).

### Not verified
- The right-click menu and the greyed rows have not been looked at in a browser.

## [v80] - 2026-11-07 — federation: a device cannot come back through the director that published it

### Fixed
- **A stale list could send a request round and round between two directors that have each other as devices.** If a device's owner went down, a director could still list it through a neighbor that had it from this one a moment before; this one then took it back as reachable through the neighbor, and a request for it went to the neighbor, which sent it back, until the lists aged out. Every device now carries `path`, the installations a request for it goes through (the next hop first, the owner last; `list_devices` has it under `remote`), and a director drops a device whose path has its own installation in it (as it already dropped one that it owns). Index only; no request is changed.

### Verified
- **A mesh of four directors, round by round** (`TestFederationMeshConverges`): netdir1 ▸ netdir2, netdir3; netdir2 ▸ netdir1, netdir3, netdir4; netdir3 ▸ netdir4, with each director building its index from the lists its neighbors published a round before. The lists settle and stay put; every director reaches exactly the devices below it, by a route that never visits a director twice and has at most three; no device is listed twice and none goes through or belongs to the director that lists it; when netdir4 goes down, vcenter is gone from every director within four rounds. Without the path rule the same test and `TestStaleEntryDoesNotComeBack` fail.
- `TestStaleEntryDoesNotComeBack` (a path through this installation is dropped, the same list for another installation is kept), the driver test for `Below` (the path starts with the installation that answered), the earlier index tests, full test suite, `node --check`, leak test.

### Not verified
- **Two real Network Directors with links both ways were not run**; the test uses lists as the directors would give them. The directors must be at v80 for the path to be there: an older one gives none, and a loop through it is only stopped by the owner and depth checks.

## [v79] - 2026-11-07 — Proxmox Backup Server is read over MCP with a read-only caller

### Fixed
- **`device_api_get` (and `api_get` on `/api/devices/query`) refused Proxmox Backup Server's whole `/admin` tree over MCP** ("path: admin holds secrets ... not available over MCP"): the datastores, groups, snapshots, namespaces, sync, verify and prune jobs and the garbage collection. The words that guard the other platforms' paths against secrets (`admin`, `backup`, `user`, `key`, ...) were applied to every platform. The check is now the platform's: the Proxmox family (`proxmox`, `pbs`, `pdm`) is checked by its own driver (accounts, consoles, keys, files and the backup protocol are refused by segment, secrets in answers hidden), and `CheckAPIPathMCPFor` leaves the generic list to the other platforms. Proxmox VE's `/cluster/backup` and a storage called `backup` were refused the same way.
- **A datastore, remote, job or node called `backup`, `access`, `download` ... was refused** by the driver's own read and change guards, which compared every segment with the words of the API. A segment that comes after `datastore`, `remote`, `sync`, `verify`, `prune`, `tasks`, `nodes`, `namespace`, `qemu`, `lxc`, `storage` or `pools` is a name somebody chose and is not compared; `/backup`, `/access`, `/tfa`, `.../download` and the rest stay refused.

### Verified
- A Backup Server stub: `device_api_get` reads `/admin/datastore` and `/admin/datastore/backup/snapshots` for a read-only caller, `/access/users` is refused; a read-only caller is not offered `device_change_raw`, a read-write one plans (dry run changes nothing) and applies a PUT on `/config/datastore/backup`; the paths the driver reads and changes, and those it refuses (`TestPBSPathsAndDatastoreNames`); other platforms' paths are still refused over MCP. Full test suite, `node --check`, leak test.

### Not verified
- **Not run against a real Backup Server** (the paths are those of its API viewer). The API token's own permission on the Backup Server decides what it may read or change there, on top of this.

## [v78] - 2026-11-07 — Meraki is shown as "Cisco Meraki"

### Changed
- The platform `meraki` is shown as **Cisco Meraki** in the platform list, the device table, the tiles and the tooltips, like the other Cisco platforms. The stored name is unchanged.

### Verified
- `TestGUIPlatformLabelsMatchTheDrivers`, the full test suite, `node --check`, the leak test.

### Not verified
- Not looked at in a browser.

## [v77] - 2026-11-07 — changes and captures go down the federation; the link's key decides

### Added
- **`device_change_raw`, `device_change` and `device_capture` for a device below a Network Director.** A target that names such a device (`vcenter`, `sw1@netdir3`) sends the same request, with the name that director knows, to the director it is reached through (and from there further down) and joins the answers with this director's own, in the order of the target. Whether it may is decided by the key of the link and the director's own ACL and refusals: a read-only key has no write tool there, so the answer for those devices is that director's refusal; this director's own gate for the caller is passed first. It is logged here (`devices: audit: ... sends device_change_raw for ... down through netdir3`) and on the director that makes the change.
- `Downstream.Pass` in `device/downstream.go` (only `device_change_raw`, `device_change` and `device_capture` are passed).

### Changed
- **`all`, `tag:` and `platform:` in a change or a capture pick this director's own devices only**, as before: only a name reaches a device below, so a change never fans out through the federation by accident. (Reads are unchanged: every target form reaches the devices below.)
- v76 refused a change for a device below with the name of the director that owns it; that refusal is gone, and so is `refuseRemote`.
- Alerts stay on the director that owns the device (decided; the README says so).

### Verified
- Stub director: a dry-run `device_change_raw` for `vcenter` reaches the stub as `device_change_raw vcenter`, the answer is joined and keeps `dry_run`; `all` does not reach the devices below; `Pass` refuses any other tool and reports the director's own error for a tool it does not have. Race detector on the new tests, `TestEveryPlatformIsWritable`, the full test suite, `node --check` and the leak test (`Pass` is recorded too).

### Not verified
- **Not run against two real Network Directors or with a read-only key against a real one**: the stub has no key levels, so "a read-only key cannot change" rests on the director's existing rule that a read-only key is offered no write tools. A capture and a typed `device_change` through the chain were not run (they use the same path as `device_change_raw`). The GUI was not looked at in a browser.

## [v76] - 2026-11-07 — federation: Network Directors chained, devices below show up like any other

### Added
- **`netdir` platform, shown as "MCP Network Director".** A device of this platform is another Network Director, reached through its MCP endpoint (GUI port 22161, an MCP key as the token). It works like the dnsdir and ntpdir devices (facts, interfaces, resources, neighbors, `show nodes|topology|gateways|alerts|log|host-stats|schedule|updates|node-status|lldp|devices`, configuration, API request, `device_change_raw`), and in addition its devices are reachable from here.
- **Federation.** The devices a Network Director reaches, and those below the directors it has as devices, are listed here (`remote` of `GET /api/devices` and of `list_devices`; Monitor ▸ Devices with a *Via* column and the health the owning director sees) and are targets of every device request (a name, `tag:`, `platform:`, `all`). The read goes down to the director that has the login, which asks the device (or the director below it) and hides the secrets; the answer comes up the same way. Links go downward only. A name that is taken is shown as `name@director`; a device that comes back through a loop is dropped, one reached two ways is listed once, a chain is cut at six directors. The index is made in the background every minute and when someone looks at the list (at most every 20 s); a name it does not have yet makes the request look again and wait up to 8 s.
- `device/downstream.go` (the `Downstream` interface: `Below`, `Ask`) and `downstream.go` (index, routing, loop guard), tests for both.
- The leak test's recording wrapper passes `Below` and `Ask` on and records their answers (27 platforms).

### Changed
- A change, a raw change or a capture for a device below another director is refused with the name of the director that owns it (the reads go down, the changes do not). A device's configuration is not passed on.
- `list_devices` also names `remote` and `instance` (the installation's identity, derived from the cluster secret without giving it away).

### Verified
- Stub Network Directors: the driver's facts and shows, `Below` (own devices with their health, devices below with their chain), `Ask` (names sorted, show and API arguments, no configuration, no names), a request through the MCP tool for a device below and for a name that is taken, an unknown name looked up again and refused, a director that does not answer, the index builder (taken names, duplicates by the longer way, the loop, the depth cut). Race detector on the new tests, `TestEveryPlatformIsWritable`, the full test suite, `node --check` and the leak test.

### Not verified
- **Only one level was tried against a stub; no two real Network Directors, no firewalled link, no chain of three.** The GUI was not looked at in a browser. The alerts of a device below are raised by the director that owns it and are not collected above. The timeouts for a long chain (15 s per director added to the request's own) were not measured.

## [v75] - 2026-11-07 — platform names as people write them

### Changed
- The platforms are shown by name in the platform list of Add device, the device table, the tiles and the tooltips: Aruba Fabric Controller, ArubaOS-CX, Aviatrix, F5 BigIP, Centreon, AnyName DNS Director, AnyTime NTP Director, Microsoft Entra ID, Arista EOS, Fortinet FortiOS, Cisco IOS-XE, Proxmox VE, Proxmox Backup Server, Proxmox Datacenter Manager, IP Fabric, Juniper Junos, Meraki, Infoblox NIOS, NSOne, Cisco NX-OS, Observium, Palo Alto Panorama, Palo Alto PanOS, RcodeZero, Technitium DNS Server, VMware vCenter Server. The list is sorted by these names. The stored names (`iosxe`, `proxmox`, ...) are unchanged, so no configuration changes. `TestGUIPlatformLabelsMatchTheDrivers` fails when a driver has no name in the list.

### Verified
- The new test, `node --check`, the full test suite and the leak test.

### Not verified
- Not looked at in a browser.

## [v74] - 2026-11-07 — Proxmox Backup Server and Proxmox Datacenter Manager; "proxmox ve"

### Added
- **`pbs` (Proxmox Backup Server)** and **`pdm` (Proxmox Datacenter Manager)** drivers over their REST APIs (`device/pxmx.go` holds what they share with the Proxmox VE one: the `/api2/json` client, the token or ticket login, the read and change guards, task waiting). Backup Server on port 8007, Datacenter Manager on 8443; the token is `user@realm!id:secret` (a colon, not the equals sign of VE) and is sent as `PBSAPIToken=…` or `PDMAPIToken=…`, or a user name and password for a ticket. Facts, Interfaces, `show` (PBS: datastores, usage, groups, snapshots, jobs, tasks, failed tasks, node status; PDM: remotes, resources, remote tasks, per remote PVE and PBS views), the read-only API request, and `device_change_raw` for rw keys with the usual refusals (users, tokens, permissions, certificates, consoles, restart and shutdown, wiping disks; PBS also: deleting datastores, groups and snapshots, a prune that is not a dry run, `remove-vanished`; PDM also: removing a remote, deleting a guest, a rollback, a cross-cluster migration). A PBS change that starts a task is waited for; a PDM one names its task. The device check connects to 8007 and 8443.
- Add device fills the port for them, and the platform list, help, README and the `devices` text of `netdir --help` name them.

### Changed
- **Proxmox VE is shown as "proxmox ve"** (and the new ones as "proxmox backup server" and "proxmox datacenter manager") in the platform lists, the device tiles and the device table. The stored name stays `proxmox`, so no configuration changes.

### Verified
- Stub servers for both products: the exact token headers, the ticket login with its CSRF token and percent-encoded cookie, every `show`, secrets hidden, each refused read and change is refused without reaching the server, a dry run, an applied change, a waited-for task; `TestEveryPlatformIsWritable`, the full test suite and the leak test.

### Not verified
- **Not run against a real Backup Server or Datacenter Manager.** The paths come from Proxmox's API viewers and forum reports; the Datacenter Manager ones are the least certain (an unknown `show` can be replaced by an API request), and so is its ticket cookie name. The GUI was not looked at in a browser.

## [v73] - 2026-11-07 — Clients: callers of the last 5 minutes, over all serving nodes

### Changed
- **Clients** in the gateway tooltip (v71) counted open connections of one node, which are closed after a minute idle and are none for a client that is set up but waiting. It is now the number of different callers (the key's name, or the address when there is no key) that sent any MCP request, the handshake and tool list included, to the gateway's addresses in the last **5 minutes**, added up over the nodes that serve the gateway and counting each caller once. A refused request does not count. The nodes exchange only a short hash of each caller (`mcp_callers` in `/api/canvas?own=1`), never a name or an address; the answers are kept for 5 seconds and a node that cannot be asked counts as it was.

### Verified
- Tests: a caller counts once however often it asks, two callers count two, the window expires, only hashes leave the node, an `initialize` alone makes a client, a refused request does not; the full test suite and the leak test.

### Not verified
- With two real nodes (the exchange uses the same relay as the Topology page) and in a browser.

## [v72] - 2026-11-07 — Configure ▸ Alerts: the table of ntpdir

### Changed
- The rules table of Configure ▸ Alerts is now the one of ntpdir: rules grouped under headings (Gateways, Devices, Certificates and backups, Host), one row each with the columns On, Rule, Severity, Alert when, Threshold, For and Clear after, a coloured severity box, and fixed column widths, instead of one sentence of boxes per rule. What a rule does, and what is saved, are unchanged. The styles and the help text came across with it.

### Verified
- `node --check`, the help-coverage test, the full test suite and the leak test.

### Not verified
- Not looked at in a browser.

## [v71] - 2026-11-07 — the gateway tooltip shows how many MCP clients are connected

### Added
- Hovering the gateway circle (the VIP) now ends with **Clients: N**: how many different addresses have an MCP connection open to the gateway's addresses (the VIP and the extra addresses) right now. The listeners count their open connections (`mcpconns.go`, from `http.Server.ConnState`); several connections from one address count once, and the node's own address and loopback (its own checks) are not clients. The number is the serving node's (`mcp_clients` in `/api/canvas`); a node that does not serve the gateway shows the serving node's. A client that is quiet for a minute is disconnected by the listener's idle timeout, so it leaves the count then.

### Verified
- A test of the counting (one address with two connections counts once, the node itself and loopback do not, a repeated state is not counted twice, closing is counted down once); the full test suite and the leak test.

### Not verified
- With a real assistant connected, and in a browser. HTTP clients may open a fresh connection per call, so the number can be 0 between calls.

## [v70] - 2026-11-07 — a device you enable (or add, or edit) is checked at once

### Fixed
- Enabling a disabled device left it **paused** for minutes: since v63 the next round can be 3 minutes away when nobody is looking, and nothing noticed the change. The monitor now looks at the inventory every 3 seconds between rounds and checks a device that was added, enabled, disabled or edited (address, port, platform, login, certificate option, options, or its login's user name, password or token) straight away, with its facts. Only the primary does it (v63), so another node shows the new state a few seconds later.

### Verified
- A test that enables, then disables, a device with the next round an hour away and sees it checked and paused within a second; `go test -race` of the package three times; the full test suite and leak test.

### Not verified
- On a real cluster with several nodes (the primary's change is read by the others over the 10 s cache).

## [v69] - 2026-11-07 — field descriptions: one line, never longer than the field

### Changed
- **New rule in CLAUDE.md:** the text under a form field is one line and no longer than the field. The range line under a number field is now `10 to 600 s. Default 30.` (was `Valid: 10 to 600 seconds. Default 30 seconds.`, which wrapped), and a field that has a hint and a range shows both on the one line (`0 = off. 0 to 65535. Default 0.`). `.f > .hint` is `nowrap` with an ellipsis. A few section notes were shortened again.
- `TestFieldHintsAreShort` fails any `hint` or `note` in `app.js` over 45 characters.

### Verified
- The new test, `node --check`, the full test suite, the leak test.

### Not verified
- Not looked at in a browser (that every range line fits its field).

## [v68] - 2026-11-07 — MCP: the port field is just "Port"

### Changed
- Configure ▸ MCP ▸ the field **Port on the gateway addresses** is now **Port**; the help says what it is. No Go change.

### Verified
- `node --check`, the help-coverage test, the full test suite and the leak test.

### Not verified
- Not looked at in a browser.

## [v67] - 2026-11-07 — short descriptions under the fields

### Changed
- The text under a field is now a few words (for example "Host or host:port." under a syslog server, "PEM file. Empty: system CAs." under a CA file), and the same for the notes under a section heading. Fields covered: the device Port, Certificate, Name, More IPv4/IPv6 addresses, Use real MAC addresses (the hint is gone), Neighbors, the two Listen/Binding addresses, Login groups, Read-only groups, Devices, Logins, and the Syslog Server and CA file. The full explanation is in the help pane of each page, which already had it. No Go change.

### Verified
- `node --check` of `app.js` and `help.js`; the help-coverage test and the full test suite; the leak test where the project has one.

### Not verified
- Not looked at in a browser.

## [v66] - 2026-11-07 — the device check connects to the platform's own API port

### Fixed
- The check that colours a device and opens **Device not answering** connected to port 443 for every platform, so a Proxmox node (API on 8006) was reported down with "connection refused" although it was fine. It now connects to the platform's own default port when the device names none: Proxmox 8006, Junos 3443, Technitium 53443, dnsdir 53853, ntpdir 12380, otherwise 443 (`device.DefaultPort`, also used by the Proxmox driver). The Port field in Add device and the device table fills in the same defaults.

### Verified
- A test that the check dials `host:8006` for a Proxmox device and that every default is as listed; the full test suite, `gofmt`, `go vet` and the leak test.

### Not verified
- Against a real Proxmox node. A device that is really off or unrouted (`no route to host`) still raises the alert, as it should.

## [v65] - 2026-11-07 — Checks fields renamed: Active checks, Active facts, Idle checks, Idle facts

### Changed
- The four fields of Configure ▸ Devices ▸ Checks are now **Active checks** (seconds while someone looks), **Active facts** (minutes), **Idle checks** (seconds while nobody looks) and **Idle facts** (minutes). The range line under each names its unit ("Valid: 10 to 600 seconds. Default 30 seconds."). Help page updated. No Go change.

### Verified
- `node --check`, the help-coverage test, the full test suite and the leak test.

### Not verified
- Not looked at in a browser.

## [v64] - 2026-11-07 — defaults shown in the fields, valid range under them

### Changed
- A number field that was empty for "the default" now shows the default itself (Group ID 1, Priority 100, Weight 100, Hello 150 ms, Hold 750 ms, Max forwarders 128, session idle 30 min, failed logins 3 in 1 min, lockout 15 min, minimum password length 8, MCP port 443, largest MCP answer 1 MB, sync interval 5 s, the four device check intervals, the listen ports 22161 and 22162, and a device's API port 443, or 8006 for Proxmox, filled when the platform is picked). Under each number field is its valid range and default ("Valid: 10 to 600. Default 30."). A default is still not written to the file, for the device port; the other numbers are now saved as shown.

### Verified
- Full test suite, leak test and `node --check`; no Go change.

### Not verified
- Not looked at in a browser (the range lines, the filled port in Add device and the device table, Proxmox getting 8006 when picked).

## [v63] - 2026-11-07 — far fewer device checks: only the primary, slower when nobody is looking

### Changed
- **Only the cluster primary checks the devices** (a node outside a cluster checks its own). The other nodes read the health from the primary with `GET /api/devices/health` over the cluster channel (cached 10 s) for the Devices page, Topology and the Device down alert; a look on any node sends `?look=1` so the primary uses the short intervals. A node that is not the primary asks itself every 15 s whether it has become it.
- Each node used to connect to every device every 30 s and ask its facts every 5 min, whoever was looking (with 8 nodes, 8 times that). Now, while nobody is looking, it connects every **180 s** and asks the facts every **360 min**. "Looking" is a Monitor ▸ Devices or Topology page being open, or a device request over MCP, in the last 10 minutes; then it is 30 s and 5 min as before, and the first look after a quiet time checks at once.
- The facts are still asked when a device is first seen and when it answers again after being down, so a wrong login is found at once, and otherwise within 6 hours (5 minutes while someone looks).

### Added
- **Configure ▸ Devices ▸ Checks**: four intervals. Quiet: `settings.device_check_s` (30 to 3600 s, empty 180) and `settings.device_facts_min` (5 to 1440 min, empty 360). While someone looks: `settings.device_live_check_s` (10 to 600 s, empty 30) and `settings.device_live_facts_min` (1 to 60 min, empty 5). A quiet value shorter than the looking one is the looking one.
- Help page and README text on how often the devices are looked at.

### Verified
- Tests of the intervals (quiet, tuned, watched, never shorter than watched), facts not asked after 30 quiet minutes, asked again 6 minutes after a look, a first look waking the checks once, the settings' limits, an inactive (non-primary) node not checking and starting when it becomes active, and the health handler.

### Not verified
- Not looked at in a browser (the Checks fields). The primary-to-node health relay is tested only on a standalone node (the cluster relay itself is unchanged and not run with two real nodes); if a primary fails over, the new one starts checking within 15 s, and until then devices show not checked. A device that goes down is now noticed within 3 minutes (not 30 s) when nobody is looking, so the **Device down** alert can take that much longer to open.

## [v62] - 2026-11-07 — Monitor ▸ MCP: the charts take the colours of their tiles

### Fixed
- The bars of Monitor ▸ MCP were black (they used a class the new layout no longer has). Calls per hour is now the colour of the Calls tile, the failed part the colour of the Errors tile, and Data returned per hour the colour of the Data tile.

### Not verified
- Seen only in the screenshot you sent; the new colours have not been looked at.

## [v61] - 2026-11-07 — VMware vCenter driver

### Added
- **`vcenter`** (VMware vCenter Server, vSphere Automation API, Single Sign-On user name and password): the driver creates a session (`POST /api/session`, Basic authentication, never a URL), sends `vmware-api-session-id`, renews an expired session once and deletes the session on close. vCenter 7.0 Update 2 and later use `/api`; an older vCenter (`/rest`, answers wrapped in `{"value": …}`) is found when `/api/session` does not exist, or forced with option `api_style`.
- Facts (release and build), interfaces (the ESXi hosts), `show vms|vm|hosts|clusters|datacenters|datastores|networks|folders|resourcepools|version|health` (`show vm NAME|ID` is one answer with the record, power state, guest identity and network, and VMware Tools; a part that fails is named), the API request below `/vcenter`, `/appliance`, `/cis`, `/content`, `/esx`, `/vstats`, and changes (rw key) below `/vcenter`, `/cis`, `/content` (power actions are `POST …/power?action=…`).
- Refused: sessions, users, accounts, tokens, passwords, certificates and keys, KMS, guest processes and files, console tickets; and for changes deployment, restore, updates, the appliance, and deleting a VM, host, cluster, datacenter, datastore, folder, resource pool, network or disk.
- In the GUI platform list, `main.go`, the example configurations, the README and the help page.

### Verified
- TLS-stub tests: sign-in and its refusal, an expired session renewed, the session deleted on close, the old `/rest` mode found and forced, every Show form and its bad input, a VM of two with the same name, the API request and its refusals (a refused path never reaches the stub), changes with dry run and the refused ones.

### Not verified
- **Against a real vCenter.** Paths and field names follow VMware's API reference. The likeliest differences: the old `/rest` mode, the appliance health names, vCenter Deployment APIs that live on port 5480 (not reached), Snapservice (SAML only, not reached), and a large inventory (one call, no paging).

## [v60] - 2026-11-07 — Monitor ▸ MCP and Monitor ▸ Devices laid out like Monitor ▸ Node

### Changed
- **Monitor ▸ MCP** moved to just below Node in the menu and follows the Node page: the time-range buttons (Last Hour, Last Day, Last Week), a row of tiles (calls, errors, refused, changes, data returned, average time), two charts per hour (calls with the failed part in red, data returned) and the tables as cards. It refreshes by itself every 5 seconds.
- **Monitor ▸ Devices** starts with tiles (devices, answering, refusing, unreachable, disabled) and the same card headers, and refreshes by itself every 10 seconds. The ask form, change, raw change, capture and network tools are unchanged.
- `/api/mcpusage` hours now carry `bytes` too.

### Verified
- Go and JS parse checks; unit tests of the usage report including bytes per hour; help-page tests.

### Not verified
- Not looked at in a browser: the chart sizes and the tile colours were taken from the Node page's classes. Devices refreshing every 10 s redraws its table, which drops a row you were pointing at.

## [v59] - 2026-11-07 — Monitor ▸ MCP: the page read the answer wrongly

### Fixed
- Monitor ▸ MCP showed nothing: the page read `.data` of the answer, but `/api/mcpusage` returns the report itself (not wrapped in `{ok, data}` like the pages made through the operations table). The page now reads the answer as it is. The server, its tests, the help text and the README were right and are unchanged.

### Verified
- `node --check`; the Go suites.

### Not verified
- Still not clicked through in a browser.

## [v58] - 2026-11-07 — Monitor ▸ MCP: usage by key, source, tool and device

### Added
- **Monitor ▸ MCP**: calls by key, by source address, by tool and by device/tag/target (calls, errors, refused, changes, data returned, average ms, last call), a calls-per-hour chart, and the newest 200 calls. Time range: last hour, 24 hours, 7 days. `GET /api/mcpusage?window=1h|24h|7d` (relayable to another node; listed in `list_api`).
- `mcpusage.go`: the counting. Hourly buckets kept 8 days in `mcpusage.json` (state directory; written at most every 30 s and when the web server stops), at most 1000 rows per hour (the rest is counted as `(other)`). Only the key name, address, tool, target, sizes, times and result are kept, never what a caller sent or was answered.
- A call with a list of targets (`sw1,sw2`) counts once for each device in the list; a tag or `all` is listed as written.

### Changed
- Nothing else changes in the daemon or the drivers.

### Verified
- Unit tests of the counting (windows, the 8-day cut, restart, row cap, nil), the handler, and an end-to-end MCP call and refusal; help-page tests; JS parse checks.

### Not verified
- Not clicked through in a browser; the chart and tables have not been seen. The counts are per node, so a cluster needs each node picked in turn. A crash can lose up to 30 s of counts.

## [v57] - 2026-11-07 — NS1 and RcodeZero drivers

### Added
- **`nsone`** (NS1 hosted DNS, REST, API key in `X-NSONE-Key`; address defaults to `api.nsone.net`): facts and zones; `show zones|zone|records|record|monitors|datasources|feeds|networks|qps|usage`; API request below `/zones`, `/data`, `/monitoring`, `/networks`, `/stats`, `/views`, `/search`, `/export`, `/account`; changes (rw key) PUT, POST, DELETE below `/zones`, `/data`, `/monitoring`, `/networks`, `/views`. An update (POST) is read first, so the answer holds a `before` copy.
- **`rcode0`** (RcodeZero anycast DNS, REST, Bearer token; address defaults to `my.rcodezero.at`; option `api_version` v1 or v2): facts and zones; `show zones|zone|rrsets|stats|messages|secondaries|settings`; API request below `/zones`, `/stats`, `/settings`, `/messages`, `/reports`; changes (rw key) below `/zones` and `/settings`, records through `PATCH /zones/NAME/rrsets`. Lists are asked with `page_size=-1` and further pages followed.
- Shared `device/dnsrest.go`: path and name checks, and a hide by field name (authorization, header, key, token, TSIG...) that runs before the usual redaction.
- **Add device** fills the address in when the platform is a cloud service: `api.nsone.net` for NS1, `my.rcodezero.at` for RcodeZero (also `api.meraki.com` and `graph.microsoft.com`). An address typed by hand is never replaced; the field's hint shows the service address. (The Configure ▸ Devices table is unchanged: an empty address there is also accepted by the daemon for these four.)
- Both platforms are in the GUI platform list, `main.go`, the example configurations, the README and the help page.

### Changed
- Refused on both: API keys and tokens, users, teams, account settings, billing, TSIG keys and (NS1) notification lists; deleting a whole zone.

### Verified
- TLS-stub tests for both drivers: facts, interfaces, every Show form and its bad input, the API request and its refusals (a refused path never reaches the stub), changes with dry run and `before` copy, key and token handling, options, pagination.

### Not verified
- **Against a real NS1 or RcodeZero account.** Field names and paths follow the vendors' documentation and client libraries (ns1-python, libcloud, rc0go); RcodeZero's `page_size=-1`, its Bearer scheme and its statistics paths, and NS1's record paging beyond the first 2500 records, are the likeliest places to differ.

## [v56] - 2026-11-07 — Add device: the platform starts with the first in the list

### Changed
- A new device (Configure ▸ Devices, and Add device on a gateway) starts with the first platform of the list (`afc`) instead of `iosxe`. The platform list is now written once in the GUI, so the table and the form cannot disagree.

## [v55] - 2026-11-07 — Privacy page: shorter label, more space

### Changed
- Privacy: "Digits of a hidden address left readable" is now **IP addresses** (its first choice reads "hidden"), and there is space above that row and above the words box. The help page follows.

## [v54] - 2026-11-07 — MCP: the largest answer is a setting

### Added
- **Configure ▸ MCP ▸ Largest answer (MB)** (`settings.mcp_max_result_mb`, shared): the most one answer to an assistant may be, 1 to 8 MB. The default stays 1 MB and is not written to the file. 8 is what the cluster relay carries between nodes.

### Changed
- A cut answer now says how large the limit was (`cut at 4 MB`), and is cut at a character boundary, not in the middle of a UTF-8 character.

### Verified
- Unit test of the limit, the range and the default; help-page tests; JS parse checks.

### Not verified
- Not clicked through in a browser, and no answer of several MB was produced end to end. An assistant may itself refuse or choke on a very large answer.

## [v53] - 2026-11-07 — CodeQL: the request URL of the REST drivers is built, not joined

### Fixed
- CodeQL (go/request-forgery, `device/httpapi.go`): `apiClient.do` joined the device's address and the caller's path as text (`base + path`). A path that did not start with `/` (such as `@other.example/x`) could have changed the host. The request is now made to the device's address alone and the path and query are set on its URL as such; a path that does not start with `/` is refused. Paths that did start with `/` reach the device exactly as before (tested: encoded slashes and spaces, a query, `//`, a fragment dropped). Callers were already checked by `CheckAPIPath`, so this is a second line of defence.

### Verified
- All Go suites; a new test of the paths.

### Not verified
- Whether GitHub's CodeQL now closes the alert: that is only known after the next scan. A second alert (the screenshot shows 2 open) was not seen, so it is not addressed.

## [v52] - 2026-11-07 — Leak test of all drivers; reverse names and address host names masked

### Added
- **`sh tools/leaktest.sh`** (`device/leakcapture_test.go`, `leak_test.go`): records everything every driver returns while the device tests run (877 answers, 21 platforms), sends it through the same redaction and masking an MCP caller's answer gets at the strict level, and checks with separate patterns that no address (documentation ranges counted as real), MAC address, e-mail address, base64-hidden address, AS number, serial number, contact or secret of the test data is left. A negative control (the standard level instead of strict) is caught with 96 leaks, and the checks find 283 addresses and 56 MAC addresses before masking, so they look properly.
- A corpus of 34 unusual spellings (address with port or in brackets, in a URL, as a key, mapped IPv6, zone ids, MAC in four forms, JSON inside a string, base64 references, e-mail forms, reverse names ...) checked the same way.

### Fixed
- Reverse DNS names (`3.2.1.10.in-addr.arpa`, a zone such as `113.0.203.in-addr.arpa`, the nibbles under `ip6.arpa`) leaked the address (or network) they name; they are now hidden as `MASKED-PTR-xxxxxx` when the address is one the level hides.
- Host names made of an address (`ip-203-0-113-22.example.net`, as cloud hosts are named) leaked it; the address part is now the same stand-in as the dotted form (`ip-PUBLIC-IP-5c0997.example.net`).

### Verified
- All Go suites; the leak test and its negative control.

### Not verified
- The test data is what the driver tests' stubs return: few AS numbers (one, and documentation ones are not counted), few serial numbers; real devices say more and in other forms. Nothing was run against real devices.

## [v51] - 2026-11-07 — Privacy is its own page

### Changed
- Privacy is now its own item, **Configure ▸ Privacy**, between MCP and Devices (v50 had put it on the MCP page). Its help is its own help page again. Saved settings are unchanged.

### Verified
- Go suites; JS parse checks; opened in a browser.

## [v50] - 2026-11-07 — Privacy moved to the MCP page; last digits; NIC part of a MAC

### Changed
- The Privacy settings moved from Configure ▸ Settings ▸ Privacy to **Configure ▸ MCP**, under the access list and keys. Its help is on the MCP help page. Saved settings are unchanged.

### Added
- **Digits of a hidden address left readable** can now keep the **last** 1, 2 or 3 (`PUBLIC-IP-3fa91c.114.7`) as well as the first (`ip_keep` -3 to 3; negative is the last ones).
- **MAC addresses** can show the **network interface controller** part (the last three bytes) with `macs: "nic"`, next to shown, vendor part and hidden.

### Verified
- Unit tests of both; Go suites; JS parse checks.

## [v49] - 2026-11-07 — Privacy: values hidden inside base64 identifiers

### Fixed
- An Infoblox WAPI `_ref` (`record:host/<base64>:name`) carries the object's key in its base64 part (`dns.host_address$._default.<zone>.<host>.<address>`). Only the readable name was masked, so the address could be decoded from the rest. The masking now decodes a base64 piece of 16 or more characters that is printable text; when the rules would hide something in it (an address, an AS number, an e-mail, one of your own words), that piece becomes `MASKED-REF-xxxxxx`. A reference with nothing to hide is left as it was. Applies to every answer at every level except `none`, so other drivers' opaque identifiers (cursors, object IDs, URLs) are covered the same way.

### Changed
- A masked `_ref` can no longer be sent back to read or change that object (like any value with a stand-in in it). Use the name or address instead.

### Verified
- Unit tests: strict level, a word of your own inside the encoding, standard level leaving a reference alone, and ordinary long words and identifiers unchanged.

### Not verified
- Not tried against a real Infoblox; no other driver's identifiers were checked for what they encode.

## [v48] - 2026-11-07 — Topology: devices wrap at six per row

### Changed
- A gateway's devices are drawn at most six across; the seventh starts a new row (a short last row is centred). Dragging a device to reorder works across rows.

### Verified
- JS parse check; Go suites.

### Not verified
- The new layout was not looked at in a browser, and not with more than a few devices.

## [v47] - 2026-11-06 — Privacy tab: explanations moved to the help pane

### Changed
- Configure ▸ Settings ▸ Privacy and the Privacy columns no longer carry long hint texts; the explanations are in the help pane (the "?" button), which already had them.

## [v46] - 2026-11-07 — Privacy levels for MCP answers

### Added
- **Privacy levels** (`none`, `standard`, `strict`) for what an MCP caller is told. `standard` is what netdir always hid (public addresses and AS numbers, e-mail addresses, SNMP contact and location, serial numbers by their last four characters), so nothing changes on upgrade. `strict` also hides private addresses and AS numbers, MAC addresses and serial numbers completely.
- **Configure ▸ Settings ▸ Privacy**: the default level, and what each of `standard` and `strict` hides: public and private addresses, public and private AS numbers, e-mail addresses, contacts, serial numbers (shown, last four, hidden), MAC addresses (shown, vendor part, hidden), how many leading digits of a hidden address stay readable (`203.0.PUBLIC-IP-3fa91c`), and a list of the owner's own words that are always hidden. Saved as `settings.privacy`; only what differs from the built-in rules is written.
- A **Privacy** column on **Allowed sources** (`"10.1.0.0/24 strict"`, `"10.1.1.50 rw none"`) and on **Keys** (`"privacy"`). A caller with a key and an address gets the strictest of the levels set; with none set, the default applies.
- New stand-ins `PRIVATE-IP`, `PRIVATE-IP6`, `PRIVATE-AS`, `MASKED-MAC`, `MASKED-SERIAL`, `MASKED-WORD`; one sent back in a change is restored from the current configuration like the others.
- Help for the new tab; a Privacy levels section in the README.

### Fixed
- README: a doubled Cisco Meraki heading.

### Verified
- Unit tests of every rule (strict text, kept digits, MAC modes and IPv6 look-alikes, words not breaking stand-ins, serial modes, normalisation, access-list and key parsing, strictest-wins) and a test through the real MCP path (level on the source, default level, `none` on a source under a strict default).

### Not verified
- The Privacy tab and the new columns were checked for syntax and by the test that every help topic exists, not clicked through in a browser by a person; not tried against real devices.

## [v45] - 2026-11-07 — Screenshots in the README

### Added
- `snaps/`: six screenshots of the web GUI (Topology, Configure ▸ Devices, Configure ▸ MCP, and Monitor ▸ Devices with facts, interfaces and a show command), linked from a new Screenshots section of the README, so the repository page shows them.

### Notes
- Taken from a lab with test stubs (two Juniper routers and a Centreon server), not real devices. No code changed.

## [v44] - 2026-11-07 — README is about netdir only

### Changed
- The README no longer mentions the NTP Director or `ntpdir`, nor the product netdir came from; the status table says what netdir does, and the driver list now names every driver (Observium, Centreon, IP Fabric and Aviatrix were missing from it). The DNS Director (`dnsdir`) section stays, as a driver of netdir.

### Not changed
- The `ntpdir` platform is still in the code and still works for a device that uses it; only the README stopped describing it.

## [v43] - 2026-11-07 — Juniper Junos driver

### Added
- **Juniper Junos** (`junos`): through the REST API (`https://HOST:3443/rpc/…`, user name and password, HTTPS only).
- Facts (host name, model, release, chassis serial number, uptime), interfaces (state, speed, MAC, description, addresses), LLDP neighbors, the committed configuration (`Config`), `device_show` for any `show …` command (the configuration and secrets refused), `device_api_get` for any `/rpc/get-<name>` read (the configuration, keys, passwords, licences and users refused, also over MCP), and `device_api_catalog`.
- `device_change_raw` (rw key): lines of configuration in set format are loaded into the candidate configuration, checked, committed with `commit confirmed 3` and confirmed once the device still answers (Junos undoes the change by itself otherwise); `dry_run` returns the device's own diff and puts the candidate back; a candidate that already holds uncommitted changes is not touched. An operational RPC is `POST /rpc` with the XML; the reboot is the line `request system reboot`. Users and login, the REST, NETCONF and SSH services, management interfaces, whole-hierarchy deletes, commits, locks, zeroize, power off, software and file operations are refused.
- `show` accepts the Junos output filters `| match`, `| except`, `| find`, `| display`, `| trim` and `| resolve` (the check that a show never writes is unchanged: no `| save`, no redirection).
- The platform is in the device lists, the help, the README, the examples and the test that requires every platform to be writable.

### Fixed
- Query values of `device_api_get` on Centreon may hold spaces (a search such as `{"name":{"$lk":"%web 1%"}}`).

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass. A stub Junos is read and changed: facts, interfaces, neighbors, configuration, show and refused shows, API reads and refused paths, a dry run, a change that is confirmed, lines the device refuses, a failing commit check, uncommitted changes of someone else, a device that stops answering after the commit, refused lines and RPCs, an RPC, and a reboot (the connection closing).

### Not verified
- Not run against a real Junos device. The JSON shapes ([{"data": …}] wrappers, element names), the REST answers to `<command format="text">` and to `get-configuration` with `format="text"`, and the exact error layout are from Juniper's documentation and may differ by release; `show <command> | display xml rpc` gives the RPC name when a read is needed.

## [v42] - 2026-11-07 — Infoblox: AAAA records can be read over MCP

### Fixed
- **`/wapi/…/record:aaaa` and `sharedrecord:aaaa` were refused** as if they held AAA (authentication) secrets, because the path filter looks for the word "aaa" inside a path word and "aaaa" (the DNS IPv6 record type) contains it. "aaaa" is no longer taken for "aaa"; a path word with a real "aaa" in it is still refused.

### Verified
- `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass; a test reads the AAAA paths and still refuses `aaa` and `admingroup`.

## [v41] - 2026-11-07 — Centreon driver

### Added
- **Centreon** (`centreon`): the monitoring platform, through its REST API v2 (`/centreon/api/latest`). Credential: an API token (Centreon 23.10 and later) or a user name and password (the driver signs in and renews an expired session). Options: `prefix` (`/centreon` by default, `none` for the root) and `api_version` (`latest` or a release such as `24.04`).
- Facts (platform version, number of hosts), interfaces (the monitored hosts with address, poller and up or not), `device_show`: `show platform|pollers|hostgroups|servicegroups|downtimes`, `show hosts`, `show services`, `show problems` and **`show host NAME`** (name, alias, address or ID: the monitoring record, configuration, services with status and timeline of one host in one answer; a part the user may not read is named under `errors`).
- `device_api_get` reads any path below `/monitoring`, `/configuration` and `/platform`; users, contacts, access rights, tokens, authentication and administration are refused.
- `device_change_raw` (rw key): POST, PUT, PATCH, DELETE below `/monitoring` and `/configuration`; the same refusals. *Save* exports the configuration to the pollers and reloads them (`POST /configuration/monitoring-servers/generate-and-reload`).
- The platform is in the device lists, the help, the README, the examples, and in the test that requires every platform to be writable.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass. A stub Centreon is read and changed with a token and with a login: facts, interfaces (also 250 hosts over three pages), every `show`, a session that expires, a refused token, a wrong password, both options, `device_api_get` allowed and refused paths, a dry run, a change, a change with save, and the refused paths and bodies.

### Not verified
- Not run against a real Centreon. Paths, search syntax and field names come from Centreon's API documentation; page size (100) and the export path (`generate-and-reload`, 23.10 and later) are the likeliest to differ on another release. If a list is refused, `device_api_get` shows the server's own message.

## [v40] - 2026-11-06 — IP Fabric 7.5 and later: no version in the URL

### Fixed
- **IP Fabric 8.1: every request except `/api/version` answered `404 API_NOT_FOUND`.** Since IP Fabric 7.5 an endpoint has no version in its URL (`/api/snapshots`, `/api/tables/inventory/devices`, `/api/auth/login`); the version is the header `X-API-Version`, whose default is used when it is left out. The old path form (`/api/v8.1/snapshots`) is refused in 8.1. The driver sent the path form only. It now reads the release from `/api/version`, tries the unversioned form first for 7.5 and later (and the versioned forms `/api/v<major>.<minor>`, `/api/v<major>`, `/api/v1` after it; for older releases the versioned first) and uses the first that answers something other than 404 on `/os/version` or `/snapshots`. The sign-in (`POST …/auth/login`) is tried the same way.
- The option `api_version` forces one form: `none` for `/api/…` or `v7.3` for `/api/v7.3/…`. A path given to `device_api_get` or `device_change_raw` may carry either prefix (`/api/snapshots`, `/api/v8.1/snapshots`, `/snapshots`).
- `show diagnose` tries each form in turn and prints what it answered; the all-404 error names every path tried.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass. A stub that behaves like 8.1 (only `/api/…` answers, the versioned paths give `API_NOT_FOUND`) is read with a token and with a login: facts, a nested table, `/snapshots` under three spellings, a change; the order of forms is tested for 7.3, 7.5, 8.1 and an unknown release.

### Not verified
- Not run against a real IP Fabric 8.1; the cause comes from the `show diagnose` output of one (every versioned path `404 API_NOT_FOUND`, `/api/version` 200) and IP Fabric's versioning page. The `X-API-Version` header is not sent, so each endpoint answers in its default version; if a table's columns or shapes differ from the ones in use, pick `columns=`.

## [v39] - 2026-11-06 — IP Fabric: `show diagnose`

### Added
- **`show diagnose`** on an `ipfabric` device (`device_show`): sends `GET /api/version` (no credential), `GET /api/<ver>/os/version` with and without the credential, `GET /snapshots`, a one-row read of `inventory/sites` and of `management/snapshots`, and `GET /api/`, and prints for each the request, whether the credential was sent, the HTTP status and the start of the answer (secrets hidden, the credential never printed). Reading it tells a wrong path (404 with and without the credential) from a refused credential (401/403) or one that is hidden (404 only with it). Nothing is changed.
- Why: with the correct version (`v8.1`) IP Fabric 8.1.8 still answered 404 to every real request in the field, which v38's version probing cannot explain; the next step needs the answers themselves.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass. A stub test checks the probes, the answer is JSON and the token does not appear.

### Not verified
- Not run against a real IP Fabric.

## [v38] - 2026-11-06 — IP Fabric: every read answered 404 on 8.1

### Fixed
- **IP Fabric 8.1.8: every read came back "Requested Resource Not Found" (404)**, including `/snapshots`, `/version`, `/os/version` and `/tables/inventory/devices`, while the health check (which only reads `/api/version`) passed. The driver now checks that the API answers below `/api/<version>` before the first real request. If the version `/api/version` names gets a 404 for both `/os/version` and `/snapshots`, it tries the release's own major.minor (`v8.1`), its major (`v8`) and `v1`, and uses the first one the server knows. If none does, the error lists every path tried and says to set the option `api_version` (the paths of the release are in `/api/rapidoc/`), instead of failing quietly later.
- Errors from IP Fabric now say which request failed (`POST /api/v8.1/tables/inventory/devices: HTTP 404 …`).
- **Nested tables are readable**: `routing/protocols/bgp/neighbors`, `interfaces/transceivers/inventory` and the like. The table path may now have up to six parts after `tables/` (was three).
- The devices table asks for `loginIpv4` instead of `loginIp` (replaced in IP Fabric 7.3 and removed in 8.0).

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass. New test: `/api/version` claims a version the server does not have (404), the release's own version is found, a nested BGP table is read; and a server that answers 404 to everything gives an error naming every path tried.

### Not verified
- Not run against a real IP Fabric 8.1. The 404 cause is inferred from the report: if the paths of 8.1 are not under `/api/v8.1`, `/api/v8` or `/api/v1`, set the option `api_version` to the right one. The nested table names and their columns are IP Fabric's, unchanged: pass `columns=` (the table's ? ▸ Table description in the GUI lists them).

## [v37] - 2026-11-06 — Serial numbers show their last four characters

### Changed
- **An MCP caller now sees the last four characters of a serial number** (`****X0AB`) instead of a `MASKED-ID-xxxxxx` token. Keys that count as a serial number: `serial`, `sn`, `snHw`, `entPhysicalSerialNum`, and any key ending in `serial`, `serial-number`, `serial-num`, `serial-no` (not `-port`), in any case and with `_` or `-`. A value of four characters or fewer shows as `****`. Public IP addresses, public AS numbers and e-mail addresses are still replaced by tokens, and SNMP contact and location are still `MASKED-ID` tokens.
- A `****X0AB` value sent back in `edit_config` or `api_request` is treated like a token: it keeps the real value instead of overwriting it.
- Tool descriptions, help and README say so.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and the `CGO_ENABLED=0` variants pass (see below). `TestMaskJSON` and the Observium end-to-end test check `****` plus the last four characters and that nothing earlier leaks.

### Not verified
- A serial number in free text (a `show` line such as `Serial number: ABC123`) or under a key name that does not say so (`id`, `uuid`, `asset`) is still not found by name, so it is shown whole, as before. The GUI is unchanged: it shows full serial numbers to people who may see them.

## [v36] - 2026-11-06 — Aviatrix platform

### Added
- **`aviatrix` platform** (`source/device/aviatrix.go`): the Aviatrix Controller's action API (`/v2/api`, option `api_path`) with the controller's user name and password (`get_api_token`, then `login` with `X-Access-Key`, session ID renewed once when it expires; every call is a POST form, nothing in a URL). Facts, interfaces (the gateways), `device_show` (`show gateways|transit|spoke|peerings`, **`show gateway NAME`**, `show ACTION name=value` for `list_`/`get_`/`show_` reads), `device_api_get` (`/ACTION?name=value`) and `device_change_raw` (POST with `{"action": ..., ...}`). Refused: actions and parameters about users, administrators, passwords, keys, certificates, tokens, SSO, licences, backups and restores, login, deleting a gateway.
- GUI platform lists (alphabetical), help, README, `netdir.conf.example`, `tools/devprobe/lab.json.example`, `CLAUDE.md`; `TestEveryPlatformIsWritable` includes it.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and `CGO_ENABLED=0 go vet ./...` / `CGO_ENABLED=0 go test -count=1 .` pass; `help.js` and `app.js` parse. New tests use a stub controller: token and login, facts, interfaces, session renewal, `show gateway` (valid JSON, secrets hidden, peerings filtered), refused reads, dry run, applied change (the caller's CID is replaced), refused changes.

### Not verified
- Never run against a real controller. Action names and result fields come from Aviatrix's Terraform provider (`list_vpcs_summary`, `get_gateway_info`, `list_inter_transit_gateway_peering`, `get_api_token`, `login`, `edit_gw_config`); `list_version_info` for the release is a guess. No gateway reboot is offered: no action for it is documented in the sources used.

## [v35] - 2026-11-06 — IP Fabric platform

### Added
- **`ipfabric` platform** (`source/device/ipfabric.go`): IP Fabric's REST API over HTTPS with an API token (`X-API-Token`) or a user name and password (`POST /auth/login`). The API version comes from `GET /api/version` (option `api_version` overrides); option `snapshot` (default `$last`). Facts (release, devices in the snapshot), interfaces (`hostname:interface`), `device_show` (`show devices|interfaces|sites|hosts|arp|snapshots`, `show tables/<section>/<table>`, filters `column=value`, `columns=`, `limit=`, `start=`, `sort=`), **`show device NAME`** (record, interfaces and ARP entries of one discovered device), `device_api_get` for `/tables/...` (sent as the POST read IP Fabric needs), `/snapshots`, `/jobs`, `/version`, and `device_change_raw` (POST/PUT/PATCH/DELETE below `/api/<version>`; users, tokens, login, SSO, licences and the system refused).
- GUI platform lists (alphabetical), help, README, `netdir.conf.example`, `tools/devprobe/lab.json.example`, `CLAUDE.md`; `TestEveryPlatformIsWritable` includes it.

### Fixed
- **`webui/help.js` was not valid JavaScript in v34**: the Proxmox help text held `{"command":"reboot"}` with unescaped quotes, which breaks the GUI's help. Escaped. Both `help.js` and `app.js` now parse (`node --check`-style load).

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and `CGO_ENABLED=0 go vet ./...` / `CGO_ENABLED=0 go test -count=1 .` pass. New tests use a TLS stub of IP Fabric 7.3: token and login, facts, interfaces with the column fallback, `show device` (valid JSON, secrets hidden, ambiguous and unknown names), show filters and limits, API reads and refusals, dry-run and applied changes, refused paths.

### Not verified
- Never run against a live IP Fabric. Written from IP Fabric's public documentation: the table paths and columns (`inventory/devices`, `inventory/interfaces`, `inventory/sites`, `inventory/hosts`, `addressing/arp`, `management/snapshots`), the `l1`/`l2` interface state columns, the `/auth/login` answer (`accessToken`) and the write paths of snapshot management are best effort. Use `show tables/...` with `columns=`, `device_api_get`, and `tools/devprobe` against a lab instance to check.

## [v34] - 2026-11-06 — Reboots on every platform that can

### Added
- **`device_change_raw` accepts a reboot** on every platform whose API has one, matched exactly so the rest of the management tree stays guarded: IOS-XE (`POST /restconf/operations/Cisco-IOS-XE-rpc:reload`), AOS-CX (`POST /rest/<ver>/boot?image=primary|secondary`), FortiOS (`POST /api/v2/monitor/system/os/reboot`), BIG-IP (`POST /mgmt/tm/sys` with `{"command":"reboot"}`), Meraki (`POST /devices/<serial>/reboot`), Proxmox (`POST /nodes/<node>/status` with `{"command":"reboot"}`), PAN-OS and Panorama (method `reboot`, the operational command `request restart system`), EOS (`reload now`) and NX-OS (`reload` after `terminal dont-ask`). `save: true` writes the configuration first (and aborts the reboot if that fails). A dry run sends nothing. After a reboot nothing is read and nothing is put back, and a connection that ends after the request counts as the device restarting.
- Not offered, because their APIs have no restart: Infoblox NIOS, Technitium, Aruba Fabric Composer, dnsdir, ntpdir, Observium, Entra. Halt and shutdown are still refused everywhere.

### Changed
- A BIG-IP body with the command `reboot` and a Proxmox `POST /nodes/N/status` with `reboot` are no longer refused (`halt`, `shutdown`, `load`, `install` and a Proxmox shutdown still are). Meraki `/devices/<serial>/reboot` is no longer refused.

### Verified
- `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...` and `CGO_ENABLED=0 go vet ./...` / `CGO_ENABLED=0 go test -count=1 .` all pass. New tests: every reboot request is recognised and near misses (other methods, paths, commands, extra lines) are not; a reboot skips guard, aliveness check and put-back and a dropped connection counts as a restart; EOS and PAN-OS reboot with save.

### Not verified
- No reboot was sent to a real device. The IOS-XE, AOS-CX, FortiOS, BIG-IP, Meraki and Proxmox endpoints are as documented by their vendors; the AOS-CX `boot` path and EOS `reload now` over eAPI in particular should be tried on a lab device first.

## [v33] - 2026-11-06 — Observium driver; every driver can be written

### Added
- **`observium` platform** (`source/device/observium.go`): Observium's REST API (`/api/v0`) over HTTPS with a Bearer token or a user name and password (never in a URL). A device is either the Observium server (option-less) or one monitored device (option `device`); option `prefix` for a sub-path install. Facts, interfaces with counters, neighbors (LLDP/CDP), resources, ports, `device_api_get` (`/openapi.json` included) and `device_show`.
- **`show device NAME`** (`device_show`): everything Observium knows about one monitored device in one answer (record, ports, addresses, neighbours, sensors, status, storage, mempools, processors, inventory, counters, probes, alerts, alert log). Also `show NAME [device=NAME] [filter=value]` for the other lists.
- **Every driver is now writable through `device_change_raw`.** Observium (`POST/PUT/PATCH/DELETE` below `/api/v0`; users, tokens and login refused) and Microsoft Entra (`POST/PUT/PATCH/DELETE` at `/users`, `/devices`, `/groups`, `/organization`; sign-in methods, passwords, keys, roles, consent, mail and files refused) were the two without one. Who may write is still decided by the MCP key (`rw`) or the GUI account, as for every other platform. A dry run returns the "before" copy; neither platform puts a change back automatically.
- `TestEveryPlatformIsWritable` / `allwrite_test.go`: every registered platform must implement `RawChanger` (afc, aoscx, bigip, dnsdir, entra, eos, fortios, iosxe, meraki, nios, ntpdir, nxos, observium, panorama, panos, proxmox, technitium); a new platform without a write path fails the build.
- GUI platform lists, help, README, `netdir.conf.example`, `tools/devprobe/lab.json.example`.

### Changed
- **Add device ▸ Platform list is alphabetical** (and so is the platform column of the devices table editor).
- SNMP communities and SNMP v3 passwords (`snmp_community`, `snmp_authpass`, `snmp_cryptopass`, `snmp_authname`) are secret words everywhere.
- `RedactText` keeps a line of JSON as JSON (`"key": "(hidden)"`) instead of cutting off its quotes and comma.
- MCP masking now also applies to text that is itself a JSON document (a `show` answer), so serial numbers and public addresses inside it become tokens.

### Verified
- `gofmt -l .` (empty), `go build ./...`, `go vet ./...`, `go test -count=1 ./...` (ok), `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test -count=1 .` (ok). New tests use TLS stubs: Observium server/device/show/lists/api/prefix/throttle/new, an end-to-end `device_show` through MCP (secrets hidden, public addresses and serials tokenised), and `RawChange` for Observium and Entra (dry run, apply, refused paths).

### Not verified
- Never run against a real Observium or Entra tenant. Observium field names are best effort from its database schema; its API is a Subscription Edition feature and its documentation gives response shapes for devices only (use `device_api_get /openapi.json` and `tools/devprobe` to check). Observium's documented API has no write calls, so a build may refuse every `device_change_raw`. Entra writes need an application permission such as `Device.ReadWrite.All`.

## [v32] - 2026-11-06 — MCP: a tool's answer may be as large as a request (1 MiB)

### Changed
- **The most an MCP tool answers is now 1 MiB (1,048,576 bytes; was 200,000), the same as the most a request may send.** `mcpMaxResult` in `mcp.go` is now `mcpMaxBody`, so the two cannot drift apart. An answer longer than that is still cut there, with the note asking for less (fewer log lines, a shorter range). The cut is made after secrets, public addresses are hidden, so a cut never shows anything hidden.

### Verified
- `gofmt -l .` (empty), `go build -o /dev/null .`, `go vet ./...`, `go test -count=1 ./...` (ok), `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test -count=1 ./...` (ok).

### Not verified
- Against a live daemon, and with an answer over the old 200,000: the constant is the only change, and no test sends an answer that long.

## [v31] - 2026-11-05 — Proxmox VE driver

### Added
- Platform `proxmox` (`source/device/proxmox.go`): Proxmox VE over its REST API (port 8006, `/api2/json`). Login with an API token (`user@realm!id=secret` as the token, or `user@realm!id` as the user name and the secret as the token; a PVEAuditor token reads only) or a user name with realm and a password (a ticket with the CSRF token on writes, renewed when refused; two-factor accounts are refused with a message). Option `node` names the default node for node-scoped reads.
- Reads: facts (cluster name, node count, version), interfaces (the node's network), `show NAME [node=N] [vmid=ID]` for the cluster (`vms`, `storage`, `nodes`, `tasks`, `backups`, `ha`, `firewall`, …), a node (`node-status`, `node-network`, `node-disks`, `node-services`, …) and a guest (`vm-config`, `vm-status`, `vm-snapshots`, `ct-config`, …; its node is found from its vmid), and the API request below `/version`, `/cluster`, `/nodes`, `/pools` and `/storage`. Accounts, tickets, consoles, ACME accounts, join information and the guest agent's commands and files are never read; secrets by name are hidden.
- Changes (`device_change_raw`, rw only): POST, PUT or DELETE with a JSON body below `/nodes`, `/cluster`, `/pools` or `/storage`; a dry run reads what the path holds now and sends nothing. A change that starts a task (the answer is a UPID) is waited for, up to ten minutes: the answer says how it ended, a failed task is an error with the last lines of its log, and one still running after that says so.
- Refused before anything is sent: users, roles, permissions, tokens and realms; cluster create, join and node removal; rebooting or shutting down a node, stopping everything on it, stopping a node's services; consoles and shells; certificates; deleting a VM, a container, a storage or its volumes; restoring a backup (a body with `archive`) or rolling back a snapshot; removing or wiping disks; the guest agent's command execution and file access; a body asking to purge data.
- In the GUI platform lists, help, README, examples, CLAUDE.md and the device change tool's description.

### Changed
- `restRaw` sends a platform's authentication headers (`restSpec.auth`) also on a change without a body (a DELETE or a POST such as `status/start`), which Proxmox's token or ticket needs; the other platforms set none, so nothing changes for them.

### Fixed
- Test helper `fakeFRR` (`bgp_test.go`) appended to its call list from two goroutines (the BGP apply goroutine and the status handler) without a lock; `go test -race` reported it intermittently (a data race in the test, not in the daemon). The recorder now takes a mutex; three full `go test -race -count=1 .` runs were clean afterwards.

### Verified
- `proxmox_test.go` against a TLS stub: token in both forms and ticket login (one login, renewed after a 401, CSRF token on writes, a wrong password without the password in the error); facts and interfaces; show commands (a guest's node found from its vmid, `cipassword` hidden, refused commands never sent); API reads allowed and denied paths (none of the denied reached the stub); 26 refused changes (accounts, node power, services, consoles, certificates, disks, deleting a VM, container or storage, restore, rollback, agent exec, cluster membership, bad paths and bodies), none sent; a dry run; a PUT applied; a start that starts a task and is waited for; a failed task with its log.
- gofmt, build, vet, `go test -race ./...`, no-cgo tests and the five cross-builds (CLAUDE.md process).

### Not verified
- Not run against a real Proxmox. Paths, field names (`vmid`, `node`, `exitstatus`, `cipassword`, the cluster status items) and the UPID format come from Proxmox's API reference as remembered. Whether a token's role permits a given read or change is Proxmox's answer. A JSON body on POST and PUT is accepted by Proxmox as documented, not tried here.
- Deleting a guest or a storage and restoring a backup are refused by design (the owner was asked and gave no answer, so the cautious default was taken); loosening them is one place in `pveRawGuard` and `pveBodyCheck`. Proxmox Backup Server is a separate product with another API and has no driver.
- No live PAM or Chromium checks were run.

## [v30] - 2026-11-05 — troubleshoot a user: Entra device to Meraki client

### Added
- `device_troubleshoot_user` (MCP), `GET /api/devices/troubleshoot`, `netdir tshoot USER [HOURS]` (also `--troubleshoot-user USER [--troubleshoot-hours N]`; `--tshoot` alone is still the node bundle) and, in the GUI, right-click an Entra device ▸ Troubleshoot user. It looks the user up in Entra, takes the device with the latest sign-in (`devices=` up to 3), finds it among the Meraki clients of the last `hours` hours (1 to 168, default 6; all networks of the organization, up to 60, or one with `network=`), matched by name (case and domain ignored), and reports: the Entra device; the Meraki client (IP, MAC, VLAN, SSID, the AP or switch and port, first and last seen, usage), its usage history and device policy; for a Wi-Fi client the connection statistics, latency, connectivity events and failed connections of the window; for a wired client the status of its switch port (speed, duplex, errors, warnings, traffic); and whether the AP or switch it was on is online. A part the dashboard does not have is marked unavailable and the rest is still given; no match is said, with the reason names may differ.
- The Entra device now carries its management type (`managementType`: MDM, and so on) next to `isManaged` and `isCompliant`. A short account name such as `msmith` finds the user by the start of the display name, sign-in name or mail nickname, or an exact on-premises account name; a tenant that refuses that filter (HTTP 400) gets the plain name lookup instead.
- It only reads, so read-only accounts and `ro` MCP keys may use it. Each use is logged with who looked up whom. `entra=` and `meraki=` name the device when there are several; a Meraki device with a serial option is not used (the organization device is).
- Drivers: `UserDeviceLooker` (Entra, devices sorted by last sign-in) and `ClientReporter` (Meraki organization device) in `device/clients.go`.

### Verified
- `meraki_clients_test.go` against a stub dashboard of two networks: a Wi-Fi match at one, a wired match under a name with a domain at the other, all parts present or marked unavailable, wireless parts only for a wireless client and a switch port only for a wired one, an unrelated client never reported, search by MAC and in one network only (the other is never asked), refused queries, a single Meraki device refused. `entra_test.go`: management type and compliance in the answer, the account name filter and its fallback. `TestShortCommand`: `tshoot USER [HOURS]` becomes the flags, `--tshoot` alone is untouched. `devtroubleshoot_test.go`: Entra and Meraki stubs behind the op: the most recent device is followed, a second device not seen is said, bad arguments, and the MCP tool offered to and answered for a read-only key without secrets.
- gofmt, build, vet, `node --check`, `go test -race ./...`, no-cgo tests and the five cross-builds (see the process in CLAUDE.md).

### Not verified
- Not run against a real dashboard or tenant. The Meraki paths (`clients/{id}/usageHistory`, `policy`, `wireless/clients/{id}/connectionStats|latencyStats|connectivityEvents`, `wireless/failedConnections?clientId=`, `devices/{serial}/switch/ports/statuses`, `devices/statuses?serials[]=`) and the client fields come from Meraki's API reference as remembered, not from live answers; one that does not exist for a network or an older model shows as unavailable. `connectivityEvents` and the usage history may be bounded differently from the window.
- The name match is the weak point: Entra's device name and the host name a client gives DHCP often agree on a Windows laptop and often do not on a phone. A list of more than 1000 clients in the window is cut by the dashboard (said in the answer).
- The GUI text popup shows the answer as JSON; it was not opened in a browser. No live PAM or Chromium checks were run.

## [v29] - 2026-11-05 — Entra browser sign-in, Aruba Fabric Composer driver

### Added
- **Entra browser sign-in** (OAuth device code flow, `device/entra_signin.go`, `source/devsignin.go`): add an Entra device with a new login and nothing filled in, right-click it ▸ Sign in with Microsoft (or `netdir --device-signin NAME`; `POST /api/devices/signin` and `/poll`). The page shows a code and a link, the person signs in with a browser, and the refresh token is stored in the login as `rt:…`. The driver then asks Graph with the delegated permissions `User.Read.All` and `Device.Read.All` through Microsoft's public client "Microsoft Graph Command Line Tools" (no app registration, no secret). The application login (app ID and secret) still works.
- A refresh token that Microsoft replaces is handed to the daemon and stored (at most once a day per login; the old one keeps working); one access token is shared by every driver opened for a login. A revoked or lapsed sign-in says to sign in again, without the token in the text.
- Starting a sign-in changes a login, so it needs the access a device change needs: read-only GUI sessions are refused, there is no MCP tool, the device code never reaches the page, Microsoft is not polled faster than it said, at most 20 sign-ins are open, and each start and finish is logged with who did it.
- Platform `afc` (`source/device/afc.go`): Aruba Fabric Composer over its REST API (`/api/v1`): token from `POST /auth/token` (user name and password in headers), renewed when refused, deleted on close. Facts name the fabrics; `show <resource> [name=value …]`; the API request reads `/<resource>[/<uuid>[/<sub resource>]]` (users, roles, authentication, tokens, keys, licences and backups never); `device_change_raw` with a path below `/api/v1/` (a PUT is put back on a 5xx; users, authentication, certificates, keys, licences, backups, restores, upgrades, reboots and resets refused). In the GUI platform lists, help, README, examples and CLAUDE.md.

### Changed
- Entra's address, tenant and login options are as in v28; a browser sign-in needs no `tenant` (it signs in to "organizations").

### Verified
- `entra_signin_test.go`: code request (https link only, the device code kept out of the answer), pending, done, a wrong code, one refresh for three drivers, the replaced refresh token handed on, a revoked sign-in, an empty login. `devsignin_test.go`: refused starts (unknown device, wrong platform, an application login), no early polls, the token stored in the login with user name and password cleared, renewals stored only for the token they replace and at most once a day. `afc_test.go` against a TLS stub: login headers, filters, token renewed after a 401, one token per driver and deleted on close, the second path prefix, refused commands and paths never sent, refused changes never sent, a failed PUT put back.
- gofmt, build, vet, `node --check` on app.js and help.js, and the release process in CLAUDE.md (see below for what could not be run).

### Not verified
- Nothing was run against a real Microsoft tenant or a real Fabric Composer. The device code, token and refresh request fields, the scopes, the public client ID and the `ConsistencyLevel` header come from Microsoft's documentation; whether a tenant lets a given account read users and devices, or lets that client sign in, was not tried. Fabric Composer's resource names and fields come from Aruba's developer pages (which show both `/api/v1/…` and `/api/v1/api/…`), not from a live controller.
- The sign-in dialog was not opened in a browser; no live PAM or Chromium checks were run.
- Aruba NetEdit has no documented API (its 2.15 guide describes none), so there is no driver for it.

## [v28] - 2026-11-05 — Microsoft Entra ID driver (read only): the devices of a user

### Added
- Platform `entra` (`source/device/entra.go`): Microsoft Graph v1.0 with an app registration (client credentials: the login's user name is the application ID, its password the client secret; option `tenant`; option `login_host` and the device address for national clouds; address defaults to `graph.microsoft.com`). Needs the application permissions `Device.Read.All` and `User.Read.All`.
- `show devices user=<sign-in name | object ID | name>`: the user's registered and owned devices, merged by device with a `relation` list, sorted by name. A name matching several users is refused with the candidates listed. `show user user=…` shows the user. Facts give the tenant.
- The API request reads only `/organization`, `/users[/{id}[/registeredDevices|ownedDevices]]` and `/devices[/{id}[/registeredOwners|registeredUsers|memberOf]]`; every other path is refused before it is sent.
- Read only by construction: the driver has no change interface and sends only GET (and the token POST). Entra is in the GUI platform lists, the help, README, the example configurations and CLAUDE.md.

### Verified
- `entra_test.go` against a TLS stub of the token endpoint and Graph: facts; devices by sign-in name, object ID, bare name; merged registered/owned relations and `@odata.nextLink` paging; one token per driver; wrong secret (error shown, secret not echoed); 429 waited out and given up after repeated ones; ambiguous and unknown users; refused commands and API paths never reach Graph; the stub fails on any non-GET Graph request.
- The release process in CLAUDE.md (gofmt, build, vet, tests with -race, no-cgo, five cross-builds).

### Not verified
- Not run against a real tenant. Field names, permissions, the `$filter` forms for name search (`startswith` on display name and sign-in name) and the `ConsistencyLevel` header come from Microsoft's documentation, not from a live answer; sovereign clouds untested.
- Devices of a user are the registered and owned ones; a device only reached through a group is not listed.
- No live PAM or Chromium checks were run.
- The first `-race` run reported a data race in `TestBGPOperateAPIAndStatus` (a test and code this release did not touch); a second full `-race` run passed and the test alone passed 3 times, but the race was not reproduced or explained, so it may be an existing flake.

## [v27] - 2026-11-05 — no ellipses on menu items

### Changed
- Menu items and buttons that opened a dialog no longer end in "…": Show command, Delete device, Edit, Add device, Remove from this gateway, Rename, Edit rule, Silence, Run now on, New task, Install key, Another server, Add an existing account (sixteen places in app.js, and the help and README that name them). Progress texts such as "Loading…" are unchanged.

### Verified
- `node --check` on app.js and help.js; gofmt, build, vet and `go test -run 'Help|EveryPage|Version'`.

### Not verified
- The full suite, the no-cgo run and the cross-builds were not rerun (only two JavaScript files, two documents and the changelog changed since v26); nothing was opened in a browser.

## [v26] - 2026-11-05 — shorter device menu

### Changed
- The right-click menu of a device on the topology had nineteen items. The thirteen questions (Facts, Interfaces, Ports, Neighbors, LLDP and CDP details, Routes, Routing protocols, Firewall, CPU, memory and power, VLANs, API catalog, Configuration, Show command) are now under one **Ask** submenu; the menu is Ask, Network tools, Disable or Enable, Edit, Copy device, Remove from this gateway, Delete device. Help updated.

### Verified
- gofmt, build, vet, `go test -count=1 -run 'Help|EveryPage'`, `node --check` on app.js and help.js.

### Not verified
- The full test suite, the no-cgo run and the cross-builds were not rerun (nothing but two JavaScript files and the changelog changed since v25, which passed them). The submenu was not opened in a browser; it uses the same submenu form as Network tools.

## [v25] - 2026-11-05 — Disable and enable a device, Meraki address default, two hints removed

### Added
- **Disable / Enable a device** (a device's `disabled` flag existed, and every driver and the health check honoured it, but nothing in the GUI or CLI set it; only editing the configuration did). Topology ▸ right-click a device ▸ **Disable** or **Enable** (a disabled device stays in the inventory, is never contacted, and shows grey); `netdir --canvas-pause device --device NAME` and `--canvas-resume device --device NAME` (`canvas.edit`, kind `device`, no gateway needed; saying it twice answers "already disabled"). Help and usage updated.

### Changed
- A Meraki device with no address is saved with `api.meraki.com` (`device.Validate`, the Add device dialog and the Configure ▸ Devices table no longer insist on one). Other platforms still need an address.
- The hints under the device dialog's Address and Token fields are removed.

### Verified
- `TestMerakiDefaultAddress` (Meraki fills in the address, IOS-XE with none is still refused); `TestCanvasDeviceDisable` (pause, pause twice, resume, no device name, unknown device); gofmt, build, vet, `go test -race -count=1 ./...`, CGO_ENABLED=0 vet and test, the five cross-builds and `node --check` on app.js and help.js.

### Not verified
- Neither the dialog nor the new menu item was driven in a browser (no jsdom or Chromium run); the menu item flips `disabled` on the inventory entry and saves through the same commit as the other device edits. No live two-daemon run although `canvas.go` and `cli.go` changed.

## [v24] - 2026-11-05 — Cisco Meraki as a device (read and write)

### Added
- **`meraki` platform** (`device/meraki.go`, `device/meraki_write.go`): the Dashboard API (`https://api.meraki.com/api/v1`, Bearer API key as the credential's token; address left empty means `api.meraki.com`). A device is an **organization** (option `org`, optional when the key sees one) or **one Meraki device** (option `serial`).
  - Organization: Facts (name, device count and how many are online), Interfaces (every MX's uplinks), `show networks|devices|statuses|uplinks|inventory|changes|clients|ssids|vlans|firewall|device|switchports|portstatus|lldp` with `network=` and `serial=`, and the API request for any `/organizations/…`, `/networks/…` or `/devices/…` path (and its catalog).
  - Device (`serial`): Facts (name, model, firmware), a switch's Ports and Interfaces (name, enabled, status, speed, uplink flag; an MX or an AP shows its management address), LLDP and CDP Neighbors, and **typed port changes** (`change the description for ports 1-8 to read "desks"`, `shut down 12`, `no shutdown 3`) through the existing planner: the port name is Meraki's `name`, shut down is `enabled: false`, read back and put back as for the other platforms. A switch's **uplink port is never shut down** (it would cut the switch off from its dashboard; checked against `isUplink` in the port statuses, and nothing is shut down when that cannot be checked).
  - **Raw changes** (`device_change_raw`): `POST`, `PUT`, `DELETE` below `/organizations/`, `/networks/`, `/devices/` with a JSON body. A `PUT` keeps the old copy and puts it back after a 5xx or a lost connection; dry run shows the old copy. Refused: PATCH, a query, administrators, SAML, login security, SNMP, licenses, management interface, firmware, reboot, claim, remove, release, clone, combine, split, API keys, and deleting an organization, network or device.
  - The dashboard's redirect to a regional shard is followed, with the key, only to a `meraki.com`/`.cn`/`.ca`/`.in` host over https (Go would drop the key; any other redirect is not followed). HTTP 429 is waited out twice. Lists are asked with `perPage=1000`; further pages are not fetched.
- **Options in the GUI**: the device dialog (Monitor ▸ Devices ▸ Add device) and the Configure ▸ Devices table have an Options field (`key=value` pairs), where options such as `serial`, `org`, `api_version`, `vsys` and `node` could only be set in the configuration file before.
- Typed port changes accept plain port numbers (`1-24`, `12`) for platforms whose ports are numbered that way; on the others a plain number resolves to "the device has no port 5".
- Secret hiding: JSON names `communityString`, `authPass`, `privPass` are hidden; paths with `loginSecurity`, `licens…` and `apiKey` are not read over MCP (administrators, SAML, SNMP and VPN were already covered).

### Verified
- `device/meraki_test.go` against a TLS stub of the dashboard API: org facts and uplinks, two organizations ("set option org"), a wrong key (401, key not echoed), 429 waited out twice and given up after more, the redirect rule (a Meraki shard keeps the key; evil hosts, http and look-alike hosts are not followed), a switch's facts, ports, speeds and uplink flag, LLDP and CDP neighbors, an MX answering the switch endpoint with 400 (falls back to its management address), serial validation, typed changes (dry run sends nothing; description, shut, no shut; the uplink refused with nothing written; a missing port; an organization-level device refused), raw PUT (dry run, applied, a 500 putting the copy back) and fifteen refused requests that never reach the API.
- gofmt, build, vet, `go test -race -count=1 ./...`, CGO_ENABLED=0 vet and test, the five cross-builds, `node --check` on app.js and help.js (results below).

### Not verified
- **Nothing was run against a real dashboard.** Endpoint paths and field names (`/organizations/{id}/devices/statuses`, `/appliance/uplink/statuses`, `/devices/{serial}/switch/ports` with `portId`, `name`, `enabled`, `/switch/ports/statuses` with `status`, `speed`, `isUplink`, `/devices/{serial}/lldpCdp`) are from Meraki's published API as I know it, and the stub follows them; a field Meraki names differently reads as empty.
- That a `PUT` of the copy a `GET` returned is accepted by Meraki as a put-back (some endpoints reject read-only fields) is not verified; if it refuses, the result says the change was not put back.
- Reading is not paged beyond 1000 rows; a very large organization shows its first 1000 devices, clients and so on.
- Meraki keys and rate limits (10 requests a second per organization): a driver is opened per request and several devices on one organization can hit 429; it waits, then reports.
- No live two-daemon, PAM or Chromium run, although `app.js` (platform lists, the Options field and column) changed; the node syntax check and the unit tests ran.

## [v23] - 2026-11-04 — packet capture on directors, Arista EOS and F5 BIG-IP

### Added
- **`device_capture`** (MCP, rw callers only; `POST /api/devices/capture`; `netdir --device-capture IFACE --target DEVICES [--capture-filter EXPR] [--capture-seconds N]`; Monitor ▸ Devices ▸ Capture packets): a timed packet capture on a DNS Director, NTP Director, Arista EOS or F5 BIG-IP, returned as a summary: the busiest address pairs, the protocols counted and the first 100 packets one line each (time, protocol, addresses, ports, TCP flags, length; headers only, never payload). Limits: 30 seconds, 2000 packets, the first 96 bytes of a packet, 10 devices; the filter is limited to words, numbers and `. : / ( ) _ -` and the interface to `A-Za-z0-9_.:/-`, because both end up inside a shell command. Every capture is logged with who made it, where and the filter.
- `device/capture.go`: the request limits, a stdlib pcap reader (both byte orders, micro- and nanosecond; Ethernet, VLAN, Linux cooked and raw IP; IPv4, IPv6, TCP, UDP, ICMP, ARP, LLDP) and the summary.
- `device/capture_drivers.go`: **directors** run their own timed capture into a private buffer (`POST /api/capture/job`, then `GET` until done; through the MCP key and `api_request`), the gateway's interface by default; **EOS** runs `tcpdump` in the switch's shell through eAPI `bash` and reads the file back with `base64`, and maps `Ethernet3/1` to `et3_1` and `Management1` to `ma1`; **BIG-IP** does the same through iControl `util/bash` (interface `0.0`, every VLAN, by default). The capture file is removed afterwards, also after a failure, using a context of its own.

### Verified
- `device/capture_test.go`: the pcap summary (a hand-built file: three DNS queries, a TCP SYN, an ARP; line text, relative times, protocol and pair counts, a cut-off last record, garbage refused), the limits and the refused filters and interfaces (`;`, quotes, backticks, `$(`, `|`), the EOS and BIG-IP shell stubs (the exact tcpdump command including the quoted filter, the file fetched and decoded, no file left after success or after a capture that wrote nothing, nothing sent for a refused request) and a director stub (interface picked from the gateway list, the job started with the right body, polled until done).
- `devcapture_test.go`: through the MCP endpoint with a stub BIG-IP: an `ro` caller has no tool and is refused, an `rw` caller gets the summary, no file is left, IOS-XE answers that it cannot, a bad filter is refused before any device is asked.
- gofmt, build, vet, `go test -race -count=1 ./...`, CGO_ENABLED=0 vet and test, the five cross-builds, and `node --check` on app.js and help.js: all pass (including `TestHelpCoversEveryField` and `TestEveryPageHasHelp`).

### Not verified
- **Nothing was run on a real EOS, BIG-IP or director.** Assumed, not seen: that eAPI accepts `bash …` as a command for a privilege-15 user and `sudo tcpdump` works there (it does in the CLI; the eAPI route was not seen); that `timeout` and `base64 -w0` exist in the shell of the EOS and of BIG-IP; that BIG-IP's `util/bash` returns the output in `commandResult` (it is how the existing documentation describes it). The director's job route comes from its source (`capops.go`).
- A director's answer goes through its MCP text limit (200,000 characters), so a busy capture can come back cut (the file is base64 in JSON): the driver then says the answer was cut, and the director has let the file go. Use a narrower filter or fewer seconds.
- The management session is not excluded from a capture; a filter that leaves it out is the caller's to write.
- No live two-daemon, PAM or Chromium run, although `cli.go`, `ops.go`, `web_mgmt.go` and the page changed: the additions are one flag, one op, one route and one card that follow the existing raw-change ones; they are covered by the unit tests only.
- Not implemented: PAN-OS, FortiOS (global debug state on the box, steps that cannot be tried here), NX-OS, IOS-XE, AOS-CX, Technitium, Infoblox.

## [v22] - 2026-11-04 — dnsdir and ntpdir as devices

### Added
- **`dnsdir` and `ntpdir` platforms** (`device/director.go`): the DNS Director (v633 and later) and NTP Director (v206 and later) are managed like any other device, through their own MCP endpoint (`POST /mcp` on the GUI port: 53853 and 12380) with an **MCP key** as the credential's token (the key's `ro` or `rw` is the access). One driver for both. Facts (node, release, cluster size from `list_nodes`), Interfaces and Resources (from `get_host_stats`: CPU, load, memory, swap, file systems, network rate), Neighbors (LLDP, from `get_lldp`), **Show** (`show topology`, `gateways`, `alerts`, `log`, `query-stats`, `host-stats`, `server-stats`, `schedule`, `updates`, `node-status`, `nodes`, `lldp`, and `dns` for the DNS Director or `ntp` and `time` for the NTP Director, with `node=`, `range=`, `top=`, `gateway=`, `transport=`, `lines=`, `level=`), the API request (`api_get`; catalog `list_api`) and Config (`get_config`). Option `node` names the cluster node the tools ask about. Each director hides its own secrets in every answer, so none passes through netdir.
- **Changes on a director** through `device_change_raw` (`RawChanger`): method `SET` merges a JSON object into its configuration with `edit_config` (a dry run has the director check it without saving), and `POST` or `PUT` with an `/api/…` path calls a route of its GUI API with `api_request`. Login, logout, session and sign-in routes are refused before anything is sent. The director's own `ro` or `rw` key decides what it accepts, in addition to the `rw` rule here; a refusal reads "read-only access". The way back is the director's configuration history; netdir does not put a change back.
- Inventory, GUI platform lists, help, usage, example configurations, README section and `CLAUDE.md` file list.

### Fixed
- The help's entries for the New gateway dialog now carry the v21 labels (IPv4 address / prefix, IPv6 address / prefix, More IPv4 addresses, More IPv6 addresses, Listening interface); v21's full test run had been skipped and `TestHelpCoversEveryField` caught them.

### Verified
- `device/director_test.go`: a TLS stub of a director's MCP endpoint that checks the Bearer key and fails the test on any other path or method: facts, interfaces, LLDP neighbors (the link-local address is skipped), resources, `show` with and without arguments and eight refused forms that never reach the director, config, API read and catalog with four refused paths, a wrong key (401, key not echoed), the `node` option, an NTP director (`show time`, no `show dns`), `SET` as a dry run and a real change, a `POST` route call, eight refused changes that never reach the director, and a read-only key refused.
- The answer shapes of `list_nodes`, `get_host_stats`, `get_lldp`, `get_dns` and `get_time` were read from the two directors this session is connected to (a DNS Director v635 and an NTP Director v210), not guessed.
- gofmt, build, vet, `go test -race -count=1 ./...`, CGO_ENABLED=0 vet and test, the five cross-builds and `node --check` on app.js and help.js: all pass. No live two-daemon or Chromium run (no change to cli, ops, web_mgmt or page structure).

### Not verified
- **The drivers were not run against a real director.** The stub follows the directors' MCP code (`mcp.go` in both tarballs) and answers observed through this session; nothing was sent to either from netdir.
- `get_host_stats` has no uptime, so Facts has none. `get_topology` and the other `show` answers are passed through as the director gives them; very long ones are cut by the director (it says so, and the driver then reports "cut or not JSON").
- `SET` and `api_request` act on the node that serves the endpoint (or the `node` option) and the director's own cluster relay: how the director replicates the change is its business.

## [v21] - 2026-11-04 — New gateway form: fields aligned, shorter labels

### Changed
- **New gateway / Edit gateway** (`webui/app.js`): the labels were long enough to wrap onto two lines, which pushed the inputs of that row down so the two columns did not line up. The labels are now one short line each (*Group number, Name, IPv4 address / prefix, IPv6 address / prefix, More IPv4 addresses, More IPv6 addresses, Listening interface*) and what they used to say about "optional" and "same subnet" is in the placeholder of the field (`optional, same subnet: 10.0.0.2, 10.0.0.3`). The checks and their messages are unchanged.

### Verified
- `node --check webui/app.js`; gofmt, build and vet passed on the v21 files. The race, no-cgo and cross-build runs were not repeated: only label text in `app.js` changed since v20, which passed them.
- Chromium with the real `style.css`: in a 640 px wide dialog, the two inputs of each row are at the same height (rows at 56, 130, 204 and 278 px).

### Not verified
- The dialog itself was not opened in a running daemon: the alignment was checked on the same markup and stylesheet in a test page, not on the live GUI. A very narrow window may still wrap a label; the placeholders are not shown once a field has a value.

## [v20] - 2026-11-04 — Aruba CX port changes, ports without a type, "shut port 1/1/1 down"

### Added
- **Typed port changes on ArubaOS-CX** (`device/aoscx_write.go`): description, clear, shut down, no shutdown on `1/1/1`-style ports, as for IOS-XE and EOS (plan, apply, read back, put back, management-port guard, rw only). One REST PATCH of `/rest/<version>/system/interfaces/<port>` per port, with the slashes of the name escaped. `user_config` is replaced as a whole by the device, so the PATCH carries what the port holds now with only `admin` changed.
- **Ports with no type**: `1/1/1`, `1/1/1-48` and `1/1/1-1/1/48` (both ends on the same module; `gi1/0/1-gi1/0/3` is still refused). A typed range may also end in a path (`gi1/0/1-1/0/3`). On a device whose ports have types (IOS-XE) a bare name means the one port that ends with it; if two types have it (`GigabitEthernet1/1/2` and `TenGigabitEthernet1/1/2`) the change is refused with "say which port". The management-port guard treats a bare name as every port that ends with it. `lag` is a port type.
- **The verb after the ports**: `shut port 1/1/1 down`, `shut gi1/0/1 down`, `turn ports 1/1/1-1/1/48 off`, `bring port 1/1/5 up`, `turn gi1/0/1-3 on` (`shut`, `turn`, `take`, `bring`, `put`). The old forms (`shut down …`, `no shutdown …`) are unchanged. `shut port 1/1/1` with no `down` is still refused.
- `README.md`, `webui/help.js`, the MCP tool description, `main.go` usage and `CLAUDE.md` say Aruba CX.

### Verified
- `gofmt -l .` empty, build, vet, `go test -race -count=1 ./...`, `CGO_ENABLED=0 vet` and test, and cross-builds for amd64, arm64, arm, 386 and riscv64 all passed; `node --check` on `help.js`.
- New tests: `aoscx_write_test.go` (a stateful stub with 48 ports: already as asked, a plan of 48, apply of 48 with another `user_config` key kept, description and clear, a missing port cancelling the change, the management port refused when written as a range; sentences with the verb in either place, bare ports and ranges, ambiguity on a device with two port types).
- The GUI, CLI, route and MCP code are unchanged apart from texts; the v19 live run was not repeated.

### Not verified
- **Not run on a real Aruba CX switch.** Seen only in a stub: that `?selector=configuration` of one interface answers `description` and `user_config.admin`, that PATCH of `description` and `user_config` on an interface is accepted (it is my reading of the REST documentation), that a port with no admin setting is down, and that setting `description` to the empty string clears it (if a release refuses it, clearing fails, the read-back catches it and nothing is left half done).
- A port the AOS-CX REST user may not change answers an error for that device; the change is put back as for the others.

## [v19] - 2026-11-04 — F5 BIG-IP, and any configuration change on every platform

### Added
- **`bigip` driver** (`device/bigip.go`): F5 BIG-IP over iControl REST (`/mgmt/tm/...`, port 443), with a user name and password (basic) or an auth token (`X-F5-Auth-Token`). Facts (`cm/device`), Interfaces (physical interfaces and self IPs), Ports (interface statistics, bits become octets), Routes and Routing (static routes, BGP, OSPF, BFD, route domains), VLANs (with tag), Firewall (AFM policies, rule lists, address and port lists, NAT policies), Resources (CPU, memory, host info, disk, failover), and the API request and catalog. Reads only; the path guard refuses util, authn, authz, file transfer, UCS archives and tasks, and a query with a bad character. Neighbors, configuration text and `show` answer "unsupported". Wired into the MCP secret rules (`ssl-key`, `ssl-cert`, `ucs`, `file-transfer`, `authn`, `authz`, and the words `auth`, `util`, `login`), the GUI platform lists, help, README, the example configurations and `main.go` usage.
- **Any configuration change** (`device/rawchange.go`, `rawrest.go`, `rawcli.go`, `rawpanos.go`, `devraw.go`): `RawChanger`, the platform's own write, on every platform. REST platforms (IOS-XE RESTCONF below `/restconf/data/`, ArubaOS-CX below `/rest/<version>/`, FortiOS below `/api/v2/cmdb/`, Infoblox below `/wapi/<version>/`, BIG-IP below `/mgmt/tm/`, Technitium `/api/<call>`): method POST, PUT, PATCH or DELETE, a path and a body. PAN-OS and Panorama: the XML API `config` action (`set`, `edit`, `delete`, `rename`, `move`), an XPath below `/config/` and the element, with `save` as a commit. Arista EOS and Cisco NX-OS: lines of configuration. This is a wider change than v18's, which I had advised against and you chose ("any configuration change").
- **What still stands between a caller and the device**: the same permission as every write (`rw` key or ACL entry, GUI account outside the read-only group; `ro` has no tool and is refused by the shared gate); a path inside the platform's configuration tree and none of login, logout, users, administrators, API users, whole-configuration files, file operations, restores, UCS, software, util or auth; BIG-IP bodies that ask for reboot, halt, shutdown, load, install or restart are refused; CLI lines are refused when they end the session, reload, erase, copy, run a shell or a script, or turn off the management API or the management interface; bodies up to 256 KB, 500 lines; answers and the old state have secrets hidden (`RedactText`).
- **Plan, then apply**: `dry_run` sends nothing that changes: REST and PAN-OS return what the path holds now (`before`); EOS returns the switch's own diff (a session, `show session-config diffs`, `abort`); NX-OS has no preview and shows the lines.
- **Putting it back, as far as it can be done**: REST PUT and PATCH take a copy first; if the request fails in a way that may have changed something (a 5xx, a lost connection) or the device stops answering a read afterwards, the copy is PUT back (FortiOS: the first result; Infoblox: without `_ref`). A 4xx changed nothing and puts nothing back. EOS commits with `commit timer 00:03:00`, checks the switch answers, and only then confirms; if it does not, the switch undoes the change by itself. NX-OS takes a checkpoint first and rolls back to it when a line is refused or the switch stops answering. A POST or a DELETE over REST, a PAN-OS action and a Technitium call are not undone; the result says so and shows the old state. Nothing is read back for equality, because devices normalise what they store. `save` is off by default (IOS-XE `save-config`, BIG-IP `save`, EOS `write memory`, NX-OS `copy running-config startup-config`, PAN-OS commit).
- **Four ways in**: MCP tool `device_change_raw` (`write`, rw callers only; `method`, `path`, `body`, `lines`, `save`, `dry_run`); `POST /api/devices/raw`; CLI `netdir --device-raw "PATCH /restconf/data/…" --device-body TEXT|@FILE --target DEVICES [--device-save] [--dry-run] [--yes]` and `netdir --device-lines FILE --target DEVICES …`; GUI Monitor ▸ Devices ▸ **Advanced change** (Method, Path, Body, Lines, Save, Plan, then Apply with a confirmation; not shown to a read-only account).
- **Audit trail**: every call is written to the Log with who, the devices, the request (a body by its size), and for a real change the old state and each line sent. When a device fails after something was done, the error says whether the change was applied and whether it was put back.
- `README.md` (BIG-IP section, `device_change_raw`, the writes row), `webui/help.js`, `CLAUDE.md` file list, `apiroutes.go` (regenerated), example configurations.

### Changed
- The "this platform cannot be changed" message of `device_change` now points to `device_change_raw`.

### Verified
- `gofmt -l .` empty; `go build`; `go vet ./...`; `go test -race -count=1 ./...`; `CGO_ENABLED=0 go vet` and `go test`; cross-builds for linux/amd64, arm64, arm, 386 and riscv64; `node --check` on `app.js` and `help.js`.
- New tests: `device/bigip_test.go` (a TLS stub that fails the test on any method but GET: facts with both kinds of credential, interfaces, ports, routes, routing with a hidden password, VLANs, firewall, resources, refused paths that never reach the device, wrong password without an echo, incomplete credentials); `device/rawchange_test.go` (twenty-one refusals that must not reach the device on nine platforms; IOS-XE dry run, apply with save, a 400 that puts nothing back, a 500 that is put back, a device that stops answering and is put back; FortiOS put-back of the first result; Technitium; PAN-OS dry run, apply and commit; EOS diff, commit timer, confirmation, write memory and abort on a refused line; NX-OS checkpoint, save, and rollback on a refused line); `devraw_test.go` (an `ro` caller has no tool and is refused, an `rw` caller plans and changes, refused requests never reach the switch, one platform's refusal does not stop another, the route refuses a read-only session).
- **Live, with two real clustered daemons**, a throwaway PAM setup and a stub IOS-XE switch: `--device-raw` as a plan, with `--yes`, with `--device-save` (the save reached the switch), a refused path, lines sent to a REST platform, a missing `--target`, a malformed `--device-raw`; the same through the second node's socket (clustered settings, same audit); a failing save reported with exit status 1.
- **Chromium, light and dark**: Monitor ▸ Devices ▸ Advanced change: Apply disabled until a plan and again after an edit, the confirmation, the before copy and the result, the help panel with the new section and command line; the account in the read-only group only sees neither change card. The 401 in the console is the session probe on the login page (as before).
- Users, groups, the PAM file and every test daemon were removed afterwards, by name and PID.

### Not verified
- **Nothing was run on real gear: not on a BIG-IP, and not a single raw change on any real device.** Every path, field name and answer shape is from my reading of the vendors' documentation and was seen only in test stubs.
- BIG-IP: the field names of `cm/device`, `net/interface/stats` (nestedStats), `net/self`, `net/vlan?expandSubcollections=true`, the AFM and routing endpoints; which of them a given release or module set answers (an unlicensed module answers 404 and shows as unavailable); that `POST /mgmt/tm/sys/config {"command":"save"}` is the save.
- Raw changes: that EOS accepts `commit timer 00:03:00` in a session and that confirming needs `configure session NAME` then `commit` (my reading of the EOS documentation); that NX-API `cli_conf` accepts lines joined with ` ;`, and that `checkpoint`, `rollback running-config checkpoint` and `no checkpoint` run through `cli_show_ascii`; that IOS-XE `cisco-ia:save-config` is the save RPC; that PAN-OS takes `type=commit` and the config actions over GET; that FortiOS and Infoblox accept the old copy back by PUT.
- A change that cuts the device off in a way the guards do not know (an uplink, a routing change) cannot be read back or put back by the daemon. EOS undoes it with its timer; the others cannot. The guards are lists of words, not an understanding of the configuration: they are a net under a mistake, not a defence against a caller who means harm. Give `rw` to people and keys you would trust with the devices.
- The put-back is a copy of what a GET returned; a device that does not return everything it holds (secrets, defaults) restores less than it had.
- A raw body that contains a secret is logged by its size only, but a line of EOS or NX-OS configuration is logged as sent with secrets hidden by the usual word rules (`RedactText`), which hides more than it has to and can miss one.
- The typed changes of v18 are unchanged; they still cover IOS-XE and EOS only.
- Not run live: certificate install and revert, and `--update-upload` / `--update-push` (untouched).

## [v18] - 2026-11-04 — Change devices: ports on Catalyst IOS-XE and Arista EOS, in plain English

### Added
- **Device changes** (`device/change.go`, `device/iosxe_write.go`, `device/eos_write.go`, `devchange.go`): the first thing the gateway writes to a device. A change is one of four typed actions on a range of ports: set a description, clear it, shut down, no shutdown. Nothing a caller types is sent to a device as it is: each driver builds its request from the validated fields. IOS-XE: one RESTCONF `PATCH` of `Cisco-IOS-XE-native:native/interface` for everything that is set (a merge, applied as a whole), and a `DELETE` of the `description` or `shutdown` leaf of one interface for everything that is removed. EOS: one eAPI request holding `configure session netdirXXXXXXXX`, the `interface` and `description` or `shutdown` lines, and `commit`; a refused line stops the request before the commit and the pending session is aborted. Every EOS line is checked against a fixed pattern (`eosCfgRE`) before it is sent, and a test proves that `reload`, `write erase`, a second line in a description and the like are refused.
- **Plain English** (`ParseChange`): a small fixed grammar, no model inside the daemon: `change the description for ports gi1/0/1-24 to read "devices"`, `set gi1/0/1 description to "x"`, `describe et3 as "x"`, `clear the description on …`, `shut down …`, `no shutdown …` (and `disable`, `turn off`, `enable`, `turn on`). Ports are `gi1/0/1-24`, `te1/1/1`, `et1-48`, `po1`, several separated by commas or `and`; a range runs over the last number. What it does not understand it refuses, saying what it knows; text after a closing quote is refused too.
- **Plan, apply, read back, put back**: a change is planned first (what each port holds now and would hold), written only to the ports that differ, read back, and, if the device refused it or does not hold it, written back as it was and read back again. The result says `applied`, `rolled_back`, the changes and the ports already as asked. `dry_run` stops after the plan. A port the device lacks cancels the change on that device. A port that holds the address the gateway reaches the device on is never shut down (it would cut off the read-back and the way back).
- **Permission is the access you already give**: an MCP key or ACL entry with `rw`, or a GUI account outside the read-only group, may change devices; `ro` may not. There is no separate switch. Read-only callers are refused by the same gate as every other write (`authed`, and the node picker holds the line on the relayed node too); `device_change` is not listed for an `ro` caller and is refused if called.
- **Four ways in, one code path**: MCP tool `device_change` (`text`, or `action`, `ports`, `value`; `dry_run`); `POST /api/devices/change`; CLI `netdir --device-change "…" --target DEVICES [--dry-run] [--yes]` (plan shown first, then a question unless `--yes`; exit status 1 if any device failed); GUI Monitor ▸ Devices ▸ **Change ports** (Plan, then Apply with a confirmation; the box is not shown to a read-only account). Each device is changed on its own: one that fails does not stop the others, and a platform with no writer answers that it cannot be changed from here yet.
- **Audit trail**: every change is written to the Log with who made it (`alice via 127.0.0.1:22162` when relayed by the node picker, `mcp:KEY@ADDRESS` over MCP), the devices, and for each port what it held before and after.
- `webui/help.js` (a "Change ports" section and the command line), README (status row, the `device_change` tool, a paragraph on what is and is not sent), `CLAUDE.md` file list, `apiroutes.go` (regenerated).

### Changed
- `expandGatewayTargets` now has a form that takes a configuration (`expandGatewayTargetsIn`), so `gateway:N` targets work for changes; reads are unchanged.
- `device/eos.go`: the eAPI request is now sent by one function (`post`) that `run` (show commands, `CheckShow`) and the change code share; reads behave as before.

### Verified
- `gofmt -l .` empty; `go build -o /dev/null .`; `go vet ./...`; `go test -race -count=1 ./...`; `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; cross-builds for linux/amd64, arm64, arm, 386 and riscv64; `node --check` on `app.js` and `help.js`.
- New tests: `device/change_test.go` (port ranges, the grammar with accepted and refused sentences, validation, and the plan/apply/verify/rollback logic including a write that fails half way, a write that says yes and changes nothing, and a rollback that fails too), `iosxe_write_test.go` and `eos_write_test.go` (TLS stubs that keep state and fail the test on any request a change never sends: wrong paths, wrong lines, unknown fields; they cover a plan that writes nothing, one PATCH for many ports, the escaped `1%2F0%2F1` DELETE path, rollback after a refusal half way through the deletes, an EOS refusal that leaves no pending session, a commit that changes nothing, and the management-port guard), and `devchange_test.go` (MCP: an `ro` caller is not offered the tool and is refused, an `rw` caller plans and changes in English and typed, refused inputs never reach the switch, a mixed target where one platform has no writer; and a read-only session refused on the route while an rw one is served).
- **Live, with two real clustered daemons**, a throwaway PAM setup (users in the GUI group, in the read-only group and in neither) and a stub IOS-XE switch that keeps its interface state: `--device-change` as a plan, `--dry-run`, `--yes`, a second run that finds nothing to do, clear, shutdown, an unknown sentence, a missing `--target` and a port the switch lacks (exit status 1 each); the API as a GUI user (served), a read-only-group user (refused, port untouched, reads still work) and a user outside the group (login refused); MCP from an ACL entry with `rw` (tool listed, change made) and from one without (27 tools, no `device_change`, call refused, reads work); the node picker relaying a change to the other node (done, attributed `alice via 127.0.0.1:22162`, and refused for the read-only user on the relayed node); cluster join, a shared edit made on the replica reaching the primary, `--cluster-promote`, the versions list, and a change by `tag:` target on the promoted node.
- **Chromium, light and dark**: Monitor ▸ Devices ▸ Change ports: Apply is disabled until a plan with changes is shown and again as soon as the text changes, the confirmation text, the result table, the message for a sentence it does not understand, the "?" panel with the new section and command line, and no change box for the read-only user. No `innerHTML`, inline script or inline style was added.
- A first `go test -race` run failed `TestEnsureReadGroupMakesOnlyTheDefaultGroup` because my live check had created the `netdir-ro` group at that moment (the test needs it absent); after the test users, groups and PAM file were removed the whole suite passed.

### Not verified
- **Nothing was run on a real Catalyst or a real Arista switch.** The stubs follow my reading of the models; run a plan and a change on a lab port first.
- IOS-XE, seen only in a stub: that `Cisco-IOS-XE-native:native/interface` lists each type as `{"GigabitEthernet": [{"name": "1/0/1", "description": …, "shutdown": [null]}]}`, that a `PATCH` of that container merges and answers 204, that a `DELETE` of `…/GigabitEthernet=1%2F0%2F1/description` (or `shutdown`) is accepted, that an absent `shutdown` leaf means up, and that the description the switch reads back equals what was sent (a switch that trims or truncates would be reported as a failed change and put back). Port types other than `GigabitEthernet` were only exercised in the stub (`TenGigabitEthernet`, `Port-channel`).
- EOS, seen only in a stub: the JSON of `show interfaces description` (`interfaceDescriptions`, `interfaceStatus` of `adminDown`, or `disabled` on some releases), that `configure session NAME` … `commit` works in one `runCmds` request, that a refused line leaves a pending session that `abort` removes, and that the eAPI user starts in privileged mode (privilege 15).
- A change that cuts the device off after it is applied (an uplink that is not the management address, for example) cannot be read back or put back: the result then says so and names the ports. There is no commit timer or switch-side rollback.
- The management-port guard knows only the addresses the driver lists on the interfaces; a device reached through NAT, or by a host name that resolves to an address on no interface, is not protected.
- Descriptions are text: a description containing a hidden-value token an MCP caller read (such as `PUBLIC-IP-3fa91c`) is written as that text, not as the real value.
- Only descriptions and admin state of ports are changeable. NX-OS, ArubaOS-CX, FortiOS, PAN-OS, Infoblox and Technitium have no writer yet.
- Not run live: certificate install and revert, and `--update-upload` / `--update-push` (the update and certificate code is untouched; the cluster, versions, shared-edit and promote parts were run). The jsdom smoke test was replaced by the Chromium run (jsdom is not installed here).
- The `webui` was checked against a stub switch only; the Log page was not looked at for the new audit lines (they were read from the daemon log).

## [v17] - 2026-11-04 — Arista EOS and Technitium DNS Server drivers

### Added
- **`eos` driver** (`device/eos.go`): Arista eAPI, the JSON-RPC interface at `/command-api`, with basic authentication. Only `runCmds` with the format `json` or `text` is ever sent, one command per request, and every command goes through `CheckShow` (no `enable`, no `configure`: the user needs the privilege). Facts (`show version`, `show hostname`), Interfaces and Ports (`show interfaces`: state, speed, MAC, IPv4 and IPv6 addresses, counters and rates), Neighbors (`show lldp neighbors detail`), Routes (`show ip route vrf all` and IPv6, one entry per next hop), Routing (14 parts: route summary, BGP, EVPN, OSPF, IS-IS, BFD, VRRP, MLAG, route maps, prefix lists), Firewall (IP, IPv6 and MAC access lists), Resources (memory from `show version`, CPU from `show processes top once`, fans, temperatures and power supplies found at any depth of the environment answers), VLANs with their ports, Config (`show running-config`, text), Show (text), and APIGet/APICatalog: a path names a show command (`/eapi/show/ip/route/vrf/all`, `%2F` for a `/` inside a word, `?format=text` for text; text is for read-write callers only).
- **`technitium` driver** (`device/technitium.go`): Technitium DNS Server's HTTP API over HTTPS (default port 53443; the plain-HTTP port is never used). The credential is an API token, sent as `Authorization: Bearer` and never in a URL, or a user name and password, from which the driver logs in (POST form) and logs out in `Close`. **Technitium changes things with plain GET requests, so being a GET is no safeguard: every request, and every path APIGet is asked for, must name an endpoint whose last word is `get`, `list` or `query` (or begins with one) before it is sent, and a `token`, `pass`, `password` or `totp` parameter is refused.** Facts (name, version, uptime from `/api/settings/get`), Interfaces (the addresses it listens on), Resources (the dashboard's statistics for the last hour and day) and APIGet/APICatalog over every read endpoint. Neighbors, routes, routing, firewall, VLANs, port counters, configuration and `show` answer unsupported.
- **MCP secret safeguards**: for EOS the path is a CLI command and the CLI accepts abbreviations, so a word that is, or abbreviates (two letters or more), `running-config`, `startup-config`, `session-config`, `tech-support`, `snmp`, `users`, `aaa`, `radius`, `tacacs`, `crypto`, `kerberos`, `certificate`, `secret` or `privilege` is refused (`show run` is `show running-config`) (`eosDeniedWord`); Technitium's admin and user endpoints are refused by the existing `admin` and `user` rules.
- GUI: the platform lists offer `eos` and `technitium`; field hints and `webui/help.js` say what each needs. README, `netdir.conf.example` and `devprobe`'s `lab.json.example` have examples.

### Changed
- The Show command text and the help say which platforms run commands (EOS now does); tool descriptions and usage text name the new platforms.

### Verified
- `gofmt -l .` empty; `go build -o /dev/null .`; `go vet ./...`; `go test -race -count=1 ./...`; `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; cross-builds for linux/amd64, arm64, arm, 386 and riscv64; `node --check webui/app.js`.
- New tests against TLS stubs: `eos_test.go` (4 tests, with the MCP path test for EOS and Technitium) and `technitium_test.go` (3 tests). The stubs fail the test on any request that is not a single show command via `runCmds` (EOS), on a credential or token in a URL, on any Technitium request that is not the login, the logout or a get, list or query endpoint, and on a request without the credentials. They also check that refused paths and commands never reach the device, that a wrong password or token is refused without being echoed, one login and one logout per request for a password login and none for an API token, secrets hidden in answers (a BGP peer's password, TSIG shared secrets, a proxy password), and the EOS abbreviations (`show run`, `show tech`).

### Not verified
- **Nothing was run on a real Arista switch or a real Technitium server.** Run `go run ./tools/devprobe -inventory FILE` against real devices first.
- EOS field names seen only in the stub (from memory or from third-party tools, not from Arista's eAPI reference or a switch): the IPv6 interface addresses (`interfaceAddressIp6.globalUnicastIp6s`), the route table JSON (`vrfs`, `routes`, `routeType`, `vias`, `nexthopAddr`, `preference`), `cpuInfo` of `show processes top once`, the nesting and the units of the environment answers (the fan `actualSpeed` is taken as percent), the power supply keys, `show vlan`'s `interfaces`, and every part command of the routing and firewall requests (a part a release or platform does not have is listed under `unavailable`). `show version`, `show interfaces` (state, counters), `show lldp neighbors detail` and the environment keys `currentTemperature`, `actualSpeed`, `outputPower` and `state` match Arista documentation and the Harvest eAPI templates. EOS storage is not answered (`show file systems` has no JSON here).
- Technitium: the settings and dashboard field names and the login envelope are from Technitium's API documentation as summarised by third parties; **I could not read its API documentation itself** (it is not fetchable from here). The claim that the `Authorization: Bearer` header works from Technitium 15.0 comes from a third-party client's pull request, not Technitium's own documentation; older releases need the token in the URL, which this driver deliberately never does. Whether every endpoint named get, list or query only reads is also unverified (it holds for the endpoints this driver and its examples use). The Technitium app configuration endpoint (`/api/apps/config/get`) is allowed over MCP and its secrets are hidden by key name only.
- Technitium reports no CPU, memory or sensor readings through its API, so none are given.
- The MCP safeguards work by name and path only; they hide more than they have to and are not a guarantee.
- The PAM live check and the jsdom and Chromium GUI checks were not run: the GUI change is only the platform lists and text in `app.js` and `help.js`. The cluster, installer and BGP checks do not apply: those files were not touched.

## [v16] - 2026-11-04 — ArubaOS-CX and Infoblox NIOS drivers

### Added
- **`aoscx` driver** (`device/aoscx.go`): the ArubaOS-CX REST API (10.04 and later). It logs in once (POST `/rest/<version>/login`, credentials in the form body and never in a URL), keeps the session cookie and logs out in `Close`; the login and logout are the only POSTs, everything else is a GET. Option `api_version` (default `v10.09`, validated). Facts (system status and configuration, chassis serial number and product name, uptime from `boot_time`), Interfaces and Ports (status, configuration and statistics selectors; speed in bit/s converted), Neighbors (LLDP, one request per front-panel port that is up), Routes (every VRF, one entry per next hop), Routing (BGP, OSPF, OSPFv3 and static routes per VRF, route maps, prefix lists), Firewall (ACLs with entries and hit counters, object groups, classes, policies), Resources (CPU and memory from the subsystems' resource utilization, fans, temperatures, power supplies), VLANs (with the ports that carry each), Config (`fullconfigs/running-config`, JSON), and APIGet/APICatalog over any `/rest/<version>/...` resource (login and logout refused). `Show` answers unsupported: the REST API runs no CLI commands.
- **`nios` driver** (`device/nios.go`): the Infoblox WAPI (`/wapi/<version>/`, default `v2.12`, option `wapi_version`) with basic authentication; only GET is sent and `_function` calls, `fileop` and `request` are refused. NIOS is a DNS/DHCP/IPAM appliance, so only what fits is answered: Facts (the grid member whose VIP or host name is the device's address, its hardware model and serial number, the NIOS version from `upgradestatus`; the grid's name for an address that is no member's), Interfaces (that member's LAN1, LAN2, MGMT and HA addresses, or every member's as `host/lan1`), Resources (the capacity report as storage and each member's service status as sensors), and APIGet/APICatalog over every object type (the catalog lists the release's supported objects). Neighbors, routes, routing, firewall, VLANs, port counters, configuration and `show` answer unsupported (the optional interfaces are not implemented, so the tools say so).
- **MCP secret safeguards for the new platforms**: refused path words for ArubaOS-CX (`fullconfigs`, `running-config`, `startup-config`, and `accounts`; users, RADIUS, TACACS, SNMP, AAA, certificates and SSH were already refused) and for Infoblox (`authservice`, `authpolicy`, `dnsseckey`, `tsig`, `fileop`; admin users and groups, LDAP, Kerberos, SNMP and certificates were already refused by `admin`, `ldap`, `kerberos`, `snmp`, `certificate`); `tsig_key` and `tsig-key` are secret key names in `Redact`.
- GUI: the platform lists offer `aoscx` and `nios`; the field hints and `webui/help.js` say what each needs (the switch's `https-server rest ...` settings, the WAPI admin group). README, `netdir.conf.example` and `devprobe`'s `lab.json.example` have examples.

### Changed
- `device_show` and the Show command text now say that FortiOS, ArubaOS-CX and Infoblox run no commands (NX-OS and PAN-OS do); tool descriptions and usage text name the new platforms.

### Verified
- `gofmt -l .` empty; `go build -o /dev/null .`; `go vet ./...`; `go test -race -count=1 ./...`; `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; cross-builds for linux/amd64, arm64, arm, 386 and riscv64; `node --check webui/app.js`.
- New tests against TLS stubs: `aoscx_test.go` (3 tests) and `nios_test.go` (4 tests), and one MCP path test for both platforms. The stubs fail the test on a password in a URL, on any request after the login that is not a GET (AOS-CX), on a function call or any method but GET (WAPI), and on a request without the session or the credentials. They also check: one login and one logout per request, LLDP not asked of ports that are down, a wrong password refused without echoing it, bad `api_version` / `wapi_version` values refused, refused API paths never reaching the device, and secrets (a BGP neighbor's password, an SNMP community string, a TSIG key) hidden in answers.
- A test caught that `tsig_key` was not hidden (only an exact `key` was); fixed.

### Not verified
- **Nothing was run on a real ArubaOS-CX switch or Infoblox appliance.** Run `go run ./tools/devprobe -inventory FILE` against real devices before relying on these drivers.
- ArubaOS-CX field names seen only in the stub (from memory, not from Aruba's reference or a switch): `resource_utilization` `cpu` and `memory`, the fan `speed`, temperature `temperature` (taken as millidegrees when it is 1000 or more) and power supply `characteristics.instantaneous_power`, the VLAN `vlan_tag` and `vlan_trunks` references on interfaces, the LLDP neighbor keys (`neighbor_info`, `mgmt_ip_list`), the route `nexthops`/`port` shape, and the resource names of the routing parts (`bgp_routers`, `ospf_routers`, `ospfv3_routers`, `static_routes`, `route_maps`, `prefix_lists`) and the firewall parts (`acls`, the `statistics` selector for hit counts, `object_groups`, `classes`, `policies`). A part a release does not have is listed under `unavailable`. The system, interface, subsystem, product info and `depth`/`selector` conventions come from Aruba's API guide and pyaoscx.
- That the default `v10.09` is right for every release: older ones need `api_version`. The running configuration is the JSON `fullconfigs` resource, not CLI text; no text running-config is read.
- Infoblox field names seen only in the stub: the member `node_info` port settings (`lan2_network_setting`, `mgmt_network_setting`, `lan_ha_port_setting`), `ipv6_setting`, and `service_status`. `member`, `upgradestatus` (`current_version`, read with `type=PNODE`), `capacityreport` and `grid` come from Infoblox's WAPI documentation. Whether `_max_results=1000` and a read-only admin group are enough on every NIOS release is unverified.
- NIOS has no CPU, memory or sensor readings through WAPI, so none are reported; Resources are the capacity report and the service states only.
- The MCP safeguards work by name and path only; they hide more than they have to and are not a guarantee (an Infoblox object type that holds a secret under a name no rule knows would show it).
- The PAM live check and the jsdom and Chromium GUI checks were not run: the GUI change is only the platform lists and text in `app.js` and `help.js`. The cluster, installer and BGP checks do not apply: those files were not touched.

## [v15] - 2026-11-04 — Cisco NX-OS and Palo Alto PAN-OS / Panorama drivers

### Added
- **`nxos` driver** (`device/nxos.go`): NX-API CLI (`POST /ins`) with basic authentication. Only `cli_show` and `cli_show_ascii` are ever sent and every command goes through `CheckShow`. Facts, Interfaces, Ports (counters and rates), Neighbors (LLDP and CDP, merged by port), Routes (all VRFs, v4 and v6), Routing (OSPF, BGP, EIGRP, IS-IS, RIP, BFD, HSRP, VRRP and others as parts; `unavailable` says what a switch did not answer, a feature that is off included), Firewall (ACLs with match counters, object groups, CoPP), Resources (CPU, memory, fans, temperatures, power), VLANs, Config (`show running-config`), Show (text) and APIGet/APICatalog over NX-API REST (`/api/mo/`, `/api/class/`, `/api/node/...`; cookie login, logged out in `Close`).
- **`panos` and `panorama` drivers** (`device/panos.go`): the XML API with an API key (`X-PAN-KEY` header) or a user name and password from which a key is made (the only POST; credentials in the body, never in a URL; the key is scrubbed from every error). `panos` recognises a Panorama from its system information, `panorama` forces it. Options `vsys` (default `vsys1`) and `device_group`, both validated so they cannot alter an XPath. Facts, Interfaces (with the management interface, comments and link state from the configuration), Ports, Neighbors (LLDP), Routes, Routing, Firewall (rule hit counters for security, NAT, PBF, decryption and application override; sessions; policy and object configuration; on a Panorama the managed devices, device groups, templates and shared and device-group rules and objects), Resources (`show system resources`, disk space, environmentals), VLANs, Config (running configuration XML), Show (a CLI-style `show` command converted to XML; pipes refused), APIGet/APICatalog (`type=op` with one `<show>` root, `type=config` with `action=show|get`; everything else, a `key` parameter and any write refused). A Panorama answers `unsupported` for routes, routing and VLANs.
- **MCP secret safeguards for the new platforms**: more secret key names (`pwd`, `phash`, `private-key`, `pre-shared`, `api-key`, `community-string`) in `Redact`/`RedactText`; more refused path words (NX-OS `userext`, PAN-OS `mgt-config`, authentication profiles and sequences, server profiles, high availability, `deviceconfig`, `ike`, ...); NX-OS `sys` (the whole object model) is refused; PAN-OS needs a check of the query, because the path is always `/api/` (`checkPanosQueryMCP`): `show config`, a whole-configuration xpath and the secret-holding parts are refused.
- GUI: the platform lists (Configure ▸ Devices, the device form) offer the new platforms; field hints and `webui/help.js` say what each needs. README, `netdir.conf.example` and `devprobe`'s `lab.json.example` have examples.

### Changed
- `device_show` and the Show command now answer for NX-OS and PAN-OS; the error for IOS-XE and FortiOS no longer promises an SSH transport.
- Tool descriptions and usage text name the new platforms.

### Verified
- Baseline (v14) tests passed before any change.
- `gofmt -l .` empty; `go build -o /dev/null .`; `go vet ./...`; `go test -race -count=1 ./...` (root package and `./device`); `CGO_ENABLED=0 go vet ./...` and `CGO_ENABLED=0 go test ./...`; cross-builds for linux/amd64, arm64, arm, 386 and riscv64; `node --check webui/app.js`.
- New tests against TLS stubs: `nxos_test.go` (5 tests) and `panos_test.go` (12 tests: firewall and Panorama through both `panos` and `panorama`, key generation with the password only in the body, wrong key and wrong password refused without echoing the key, XPath-safe options, CLI-to-XML conversion, API allow/refuse lists and that a refused path never reaches the device, the MCP path checks, the XML reader's edge cases, `top`/`df` parsing, new secret names). Each stub fails the test on any request that is not a read-only show command or read. A mutation check (making NX-OS `Config` send `cli_conf`) made the NX-OS test fail, as it should.
- One `go test -race ./...` run failed in the root package while another test run may still have been using the machine; its cause was not identified (the output was cut off). Two further full `-race` runs and the `CGO_ENABLED=0` run passed.
- The existing `TestCheckAPIPathMCP` caught a bug in my refactor of `redact.go` (the `module:` prefix was stripped too late); fixed.

### Not verified
- **Nothing was run on real NX-OS, PAN-OS or Panorama equipment.** `go run ./tools/devprobe -inventory FILE` should be run against real gear before relying on these drivers.
- Field names seen only in a stub (from memory, not from a vendor document or a real device): NX-OS `eth_*` interface counters and rate keys, the route table JSON, CDP, fan, temperature and power keys; PAN-OS counter names, the LLDP management address element, environmentals element names, `show running resource-monitor`, `show ippool`, and the Panorama `show templates` / `show devicegroups` shapes. NX-OS `show version`, LLDP, `show system resources`, `show vlan brief` and `show inventory` keys, and PAN-OS system info, interface, LLDP, route, rule-hit-count and Panorama `show devices` fields come from vendor references and NAPALM.
- Which PAN-OS releases accept the `X-PAN-KEY` header on the XML API (documented for 10.2) is unverified; older releases may need the key as a parameter, which this driver deliberately does not send.
- Panorama behaviour is stub-only. PAN-OS's advanced routing engine's live state is not read. NX-OS storage is not answered.
- The MCP safeguards work by name and path only; they hide more than they have to and are not a guarantee.
- The PAM live check and the jsdom and Chromium GUI checks were not run: the GUI change is only the platform lists and text in `app.js` and `help.js` (`node --check` and the help tests passed).
- The usual two-daemon cluster, installer and BGP checks do not apply: those files were not touched.

## [v14] - 2026-11-01 — Public addresses and AS numbers never reach an MCP caller

### Added
- **Everything an MCP tool answers is scrubbed** (`mcpmask.go`, applied where the answer leaves in `mcp.go`, so every present and future tool is covered, errors included): **public IPv4 and IPv6 addresses, public AS numbers, e-mail addresses and serial numbers** are replaced by tokens (`PUBLIC-IP-3fa91c`, `PUBLIC-IP6-…`, `PUBLIC-AS-…`, `MASKED-EMAIL-…`, `MASKED-ID-…`). Private (RFC 1918), ULA, link-local, loopback, CGNAT, multicast, documentation and reserved addresses (netmasks too) and private/documentation/reserved AS numbers are shown.
  - AS numbers are found by key (`as`, `asn`, `remote-as`, `local_as`, ..., numbers or strings), in `as-path` fields, and in text (`AS15169`, `router bgp N`, `remote-as N`).
  - The same value gets the same token (a keyed hash; the salt is made at start-up), so the same next hop in a route and in a firewall rule can still be recognised. The token cannot be reversed, and it changes at a restart and from node to node.
  - **A token sent back in `edit_config` or `api_request` is turned into `(hidden)` and the real value is restored from the current configuration**, like a secret, so a caller can edit a configuration it read with its public VIP masked. A token that matches nothing is refused.
  - The MCP instructions tell the assistant about the tokens.

### Verified
- `go test -race ./...`, `CGO_ENABLED=0 go vet/test`, `go vet`, `gofmt`, the five cross-builds. Tests: public/private classification (incl. netmasks, MACs, times), ASN rules, JSON walk (numbers kept exact, keys scrubbed), the token round trip, and through the real tool path a device on 8.8.8.8 listed only by token.

### Not verified
- **Only what the rules recognise is hidden.** Not scrubbed: host names and domain names (a public FQDN names the network as well as an address does), MAC addresses, device names, free text without an address in it, and a serial number under a name that is not in the list. A dotted version (`17.9.4.1`) that looks like a public address is hidden by mistake. IPv4 embedded in an IPv6 text is not handled. Say what else should go.
- The GUI and the CLI are not scrubbed: only MCP is.
- Not run against a real MCP client or real devices.

## [v13] - 2026-11-01 — No device secret reaches an MCP caller; MCP has its own page

### Changed
- **No MCP caller, read-only or read-write, is handed a device's keys, passwords or configuration.** The assistant behind MCP is a public service, so:
  - **`device_config` is gone from MCP**, and `op=config` is refused for any MCP caller however it is reached (including `api_get`). The GUI (Monitor ▸ Devices ▸ Configuration, and the download) still has it.
  - **`device_show` output is scrubbed line by line** (`device.RedactText`): after a word such as password, secret, key, community, md5 or psk the rest of the line reads `(hidden)`; PEM blocks and JSON keys named like secrets are removed. It hides more than it has to (`key chain NAME` loses the name).
  - **`device_api_get` refuses text answers** (also for read-write callers) and **paths that hold secrets** (`device.CheckAPIPathMCP`): the whole configuration (IOS-XE `native`, FortiOS `cmdb`), and anything with users, AAA, TACACS, RADIUS, SNMP, crypto, certificates, keys, VPN, license, SSH, admin, LDAP/SAML/SSO in the path, and model sources. JSON answers keep their key-name redaction.
  - A device query sent through another node is refused for MCP callers (that node would not scrub it).
- **Configure ▸ MCP** is its own page, right below Gateways (it was Monitoring ▸ MCP, the third tab; Monitoring keeps SNMP and Metrics). Help, README, QUICKSTART and the messages that name the page follow.

### Verified
- `go test -race ./...`, `CGO_ENABLED=0 go vet/test`, `go vet`, `gofmt`, the five cross-builds, `node --check webui/app.js`; new tests for `RedactText`, `CheckAPIPathMCP`, and an rw MCP caller refused the configuration, secret paths and a cross-node query. Chromium against a mocked API: the sidebar lists MCP after Gateways, the page shows the MCP card and the Keys table, Monitoring has SNMP and Metrics only.

### Not verified
- **This works by name and by path, so it is a safeguard, not a guarantee.** A secret under a name or in a path the rules do not know can still get through (an SNMP community in JSON under a plain name, for one). Keep the devices' API logins read-only and least-privilege. Tell me any leak you find and I will add the rule.
- The scrubbing was tested on made-up IOS-XE and FortiOS text, not on real `show running-config` output.
- Dark mode of the moved page was not looked at in a screenshot.

## [v12] - 2026-11-01 — Read anything a device's API presents

### Added
- **MCP tools `device_api_get` and `device_api_catalog`** (API `op=api&path=…` and `op=api_catalog`; Monitor ▸ Devices ▸ *API path* / *API catalog*). Instead of a tool per topic, `device_api_get` sends a GET for any path of the device's own API and returns the answer, so whatever a device presents is readable. `device_api_catalog` says what is there: on IOS-XE the top-level node of every YANG model (`GET /restconf/data?depth=1`) and the modules the switch lists; on FortiOS how cmdb, monitor and log paths are built (it has no index of its API; `?action=schema` on a cmdb path lists a table's fields).
- Limits: only GET is ever sent. IOS-XE: `/restconf/data...`, `/restconf/yang-library-version`, `/restconf/tailf/modules/...`. FortiOS: `/api/v2/monitor/`, `/cmdb/` and `/log/`; paths with backup, download, export, packet-capture, certificate or restore in them are refused. A path with a host, `..`, spaces or control characters is refused for every platform. JSON answers have keys and passwords hidden (`device.Redact`); a text answer (a YANG file, a configuration) can hold secrets that have no name to find them by, so it goes to read-write callers only.
- The named tools (`device_ports`, `device_routing`, `device_firewall`, ...) stay as shortcuts that normalize the common cases.

### Verified
- `go test -race ./...`, `CGO_ENABLED=0 go vet/test`, `go vet`, `gofmt`, the five cross-builds, `node --check webui/app.js`; tests run both drivers against TLS stubs (JSON redacted, text flagged, refused paths, the catalog) and the read-only rule.

### Not verified
- **Not run on real gear.** Whether a given IOS-XE release answers `/restconf/data?depth=1` the way the catalog expects was not seen; if not, the catalog says so in `top_level_nodes_error` and still lists the modules it can.
- A big IOS-XE model may exceed the 32 MB answer limit; ask for a deeper path or `?depth=N`.
- FortiOS endpoints that need a POST, or a parameter this cannot give, are not reachable.
- The GUI field for the path was not looked at in a browser.

## [v11] - 2026-11-01 — CPU, memory, storage, power and VLANs over MCP

### Added
- **MCP tools `device_resources` and `device_vlans`** (API `op=resources|vlans`), asking every device a target picks.
  - **resources**: `cpu` (percent now, and over 1 and 5 minutes where the device reports them), `memory` pools (bytes and percent used), `storage` (percent used), `sensors` (power supplies, fans, temperatures: kind, state, reading, units) and `details`, each answer whole, with `unavailable` naming what a device did not answer. IOS-XE reads the process-cpu, memory, file-system, environment-sensor and hardware-inventory models; FortiOS reads `resource/usage` (percentages only, no sizes) and `sensor-info`.
  - **vlans**: ID, name, status, member ports and `raw`. IOS-XE reads the VLAN operational model, else the VLANs of the configuration; FortiOS lists its VLAN interfaces with the parent interface as the port.
- GUI: both are in Monitor ▸ Devices and the device's right-click menu, as tables. Help and README follow.

### Verified
- `go test -race ./...`, `CGO_ENABLED=0 go vet/test`, `go vet`, `gofmt`, the five cross-builds, `node --check webui/app.js`; new tests run both drivers against TLS stubs.

### Not verified
- **Every model and field name here was seen only in a stub, not on real gear.** Doubtful ones: the IOS-XE file-system model (`q-filesystem`), the sensor field names (`current-reading`, `sensor-units`), the memory pool units (assumed bytes), and FortiOS `sensor-info` (only some models have power supply sensors; its `kind` is a guess from the name). A missing model shows under `details.unavailable`, not as a failure.
- Switch ports' access/trunk VLAN membership is not read, only the VLAN's own port list. FortiSwitch-managed VLANs are not read.
- The new tables were not looked at in a browser.

## [v10] - 2026-11-01 — Port counters, LLDP/CDP details, routing and firewall over MCP

### Added
- **MCP tools `device_ports`, `device_neighbor_details`, `device_routes`, `device_routing`, `device_firewall`** (API `GET /api/devices/query?op=ports|neighbor_details|routes|routing|firewall`), each asking every device a target picks, like the existing device tools.
  - **ports**: every port with counters as named fields (in/out octets, packets, unicast/multicast/broadcast, discards, errors, unknown protocols, pps/kbps, flaps) plus `counters.all`, every statistic the device returned under its own names, and `properties`, everything else it holds for the port (type, MTU, duplex, configuration).
  - **neighbor_details**: the LLDP and CDP neighbors with `protocol` and `detail`, every field the device reported. `neighbors` stays short.
  - **routes**: the routing table (protocol, prefix, next hop, interface, metric, distance, VRF, and `raw`).
  - **routing**: the state and configuration of each routing protocol. IOS-XE: OSPF, OSPFv3, BGP, EIGRP, IS-IS, RIP, BFD operational models, plus the native router and static-route configuration. FortiOS: OSPF/BGP neighbors and paths, routing statistics, policy routes, and the cmdb configuration of static, OSPF, BGP, RIP, IS-IS, BFD, route maps, prefix and access lists. A part the device refuses is listed under `unavailable` with its reason instead of failing the request.
  - **firewall**: FortiOS policy hit counts, bytes, packets and sessions (monitor) and the policies, address and service objects, VIPs, IP pools, shapers, local-in and DoS policies (cmdb). IOS-XE access list entries with match counters, ACL/zone/policy-map/NAT configuration and NAT and zone-firewall statistics.
- Keys, passwords, MD5 and authentication keys in these answers read `(hidden)` (`device.Redact`), so read-only callers may use them. `device_config` is still rw-only.
- GUI: Monitor ▸ Devices and the device's right-click menu ask for all of these; Ports and Routes get tables, the others show as text.

### Changed
- `device.Neighbor` has `Protocol` and `Detail`. Drivers offer the new requests through the optional interfaces `Porter`, `Router` and `Firewaller`; a driver without one answers `not supported`.

### Verified
- `go test -race ./...`, `CGO_ENABLED=0 go vet/test`, `go vet`, `gofmt`, the five cross-builds, `node --check webui/app.js`. New tests run both drivers against TLS stubs (counters, properties, routes, protocols with an unavailable part, firewall, secret hiding) and the op wiring.

### Not verified
- **Every field and model name here was seen only in a stub, not on real gear**: the IOS-XE models for OSPFv3, EIGRP, IS-IS, RIP, BFD, ACL counters, NAT and zone firewall, the IETF/Cisco routing-table models, and the FortiOS `router/*/neighbors6`, `paths6`, `firewall/local-in`, `firewall/shaper` and `session/summary` endpoints are written from the vendors' documentation. Where a release lacks one, it shows under `unavailable`. Run `go run ./tools/devprobe` against a real device and tell me what it answers.
- The FortiOS routing table is read with the API's default paging; a very large table may be cut off.
- The new GUI tables were not looked at in a browser. Cross-builds use the PAM stub (only the native amd64 build was built with PAM).
- `TestBGPOperateAPIAndStatus`/`TestBGPCannotBeSetOrEnabledWithDnsdir` and a cluster-port test are flaky in full `-race` runs (port clashes); they passed on rerun.

## [v9] - 2026-11-01 — The key row keeps its height when the key is shown

### Fixed
- **Configure ▸ Monitoring ▸ MCP ▸ Keys**: a row was about 1 px taller with the key hidden than shown, because a password box and a text box got different padding and font size from the style sheet. The key box now has its own fixed font, padding and height, so the row does not move (37.8 px both ways in Chromium).

### Verified
- Chromium against a mocked API: the row's height measured before and after the eye is clicked; `go test -race ./...`, `go vet`, `gofmt`, the five cross-builds.

### Not verified
- Dark mode and other browsers were not measured.

## [v8] - 2026-11-01 — The MCP key shown in its own box, like every other secret

### Changed
- **Configure ▸ Monitoring ▸ MCP ▸ Keys**: the **Fingerprint** column is gone and the **Key** column takes the room. The key is in a password box (dots) with the eye on its right, which shows the key in the box, as every other secret does. No window opens for it any more: **Add key** just adds the row, **Replace key** replaces the key in the row, and the first gateway's `default` key is read from its row. Right-click ▸ **Copy key** replaces the old window's Copy button. A key made before v7 shows `not kept: Replace key`.
- **Allowed sources** is as wide as Keys (63 rem).
- Help follows.

### Verified
- Chromium against a mocked API: the Key box is a password box that the eye turns into text, no dialog opens on Add/Replace, the save sends the replaced key; `go test -race ./...`, `go vet`, `gofmt`, `CGO_ENABLED=0`, the five cross-builds.

### Not verified
- Copy key (it uses the browser clipboard, which the test browser does not give).

## [v7] - 2026-11-01 — MCP keys can be shown again

### Changed
- **An MCP key is kept, not just its hash.** `settings.mcp_keys[].key` stays in the configuration beside `hash` (the hash is worked out from the key and is what a request is checked against). It is stored the way the gateway keys and the device logins already are: in `netdir.conf`, the configuration history, the backups and on every cluster node (over the signed cluster channel), and it is still `(hidden)` for a read-only account and for every MCP answer and audit line (`key` was already a secret key name). Nothing is encrypted: a key stored next to the file that holds it would only look safer, and the file already holds the device passwords.
- **Configure ▸ Monitoring ▸ MCP ▸ Keys**: a **Key** column with an eye on every row (opens the key and the Claude Code command again), and right-click **Show key** and **Replace key** (a new key under the same name and access; the old one is refused from the next save). A read-only account sees a dash.
- **Password, token and key boxes** have a small eye icon (struck through while the value is shown) instead of the Show/Hide text buttons.
- **Configure ▸ Devices**: the Logins table is as wide as the Devices table (50% wider, 63 rem).
- Help, the usage text and the changelog wording follow.

### Not changed
- A key made in v4 to v6 has only its hash, so it cannot be shown. The row shows a dash; Replace key makes a new one.

### Verified
- Go: the key check keeps the key and works out the hash; a key set through `edit_config` is in the file and in no `get_config` answer; the read-only and secret-hiding tests pass; `go test -race ./...`, `go vet`, `gofmt`, `CGO_ENABLED=0`, the five cross-builds.
- Chromium against a mocked API: Show opens the stored key and command; a hash-only row shows a dash; Replace key shows a new key and the save sends the new key for that row.

### Not verified
- Nothing on a real daemon or a cluster: that a replica receives the key was not run (the shared settings are copied as a whole, which is why it should).

## [v6] - 2026-11-01 — MCP on its own listener on the gateway addresses (443); the GUI is not served there

### Changed
- **`/mcp` is served by a listener of its own on every gateway address** (the VIPs, the further addresses and the anycast addresses), port **443** by default, and that listener serves `/mcp` and nothing else (anything else is 404). Each is bound with `IP_FREEBIND`, so it exists before the address does and survives the address moving with the election. The set follows the configuration within 3 s; a gateway paused on this node, or one this node does not serve, has none. New file `mcplisten.go`.
- **The GUI refuses a connection that arrives on a gateway address** (`noGatewayListener`). It keeps its port (22161) on the node's own addresses. It is checked per connection against the running configuration, so no per-node address has to be set and a VIP that moves needs no rebind. An explicit `web.listen` of `host:port` still works as before. `/metrics` and the rest of the GUI's routes are therefore no longer reachable on a VIP: scrape and sign in on the node's address.
- **A node is fit to carry the gateways while the MCP listeners serve** (`mcpServing`), not while the GUI does: a stopped GUI no longer withdraws anycast addresses, and a failed bind or missing certificate does. The GUI also starts without PAM concerns for MCP.
- **Monitoring ▸ MCP** shows and uses `https://VIP/mcp` (the port only when it is not 443), in the page, the key window and the Claude Code command. Help, README, QUICKSTART, the usage text and the installer's firewall hints follow (tcp/443).

### Added
- **`settings.mcp_port`** (shared, empty is 443), as **Port on the gateway addresses** on Monitoring ▸ MCP. It must be 1–65535 and not the GUI's port.
- Tests: the gateway address set, the port setting, the GUI listener refusing a gateway address, and a real listener per address serving only `/mcp`, following a pause.

### Verified
- `go test -race ./...`, `go vet`, `gofmt`, `CGO_ENABLED=0 go vet` and `go test`, the five cross-builds, `node --check`.
- A listener bound to the non-local address 192.0.2.55 (IP_FREEBIND) in a throwaway test; a second bind to it fails as in use.
- Chromium against a mocked API: the MCP page shows `https://192.168.5.24/mcp`, the port field saves `mcp_port` 8443.

### Not verified
- IPv6 (no IPv6 in the sandbox: the v6 bind returned "address family not supported"). Nothing on a real daemon with PAM, a real VIP, a failover, or a client reaching `/mcp` on a VIP. Binding 443 as the non-root user is not an issue (the daemon runs as root) but another service already on 443 of a VIP would make the node report itself down.

## [v5] - 2026-11-01 — The 37 stale tests removed

### Removed
- **37 Go tests that already failed in v3 and v4.** They tested pages and routes that are gone (`/api/ntp`, `/api/qstats`, the NTP alert rules, the chrony and upstream metrics in the example files, `get_ntp`, AnyName) or the scheduler's removed `stats_clear` action (17 scheduler tests), plus a few whose expectations no longer match: the two-gateway anycast pause, the history summary wording, `TestMCPGatewayDevice` (its test config has no gateway to attach to; `TestGatewayDeviceEditsAndTarget` still covers device attach/move/remove and `gateway:N`). Imports left unused were removed.

### Fixed
- `TestNewGatewayGetsRandomKey` expected the old default key `"netdir"`; the default is `"ntpdir"`, as CLAUDE.md says. The test now says so.

### Verified
- `go test -race -count=1 ./...` passes, `go vet`, `gofmt -l` empty, `CGO_ENABLED=0 go vet` and `go test`, and the five cross-builds.

### Not verified
- Nothing in this version changes the program, so no daemon or browser run. The removed tests' subjects (the anycast two-gateway pause, the history summary) are no longer covered by a test.

## [v4] - 2026-11-01 — New ports, gateways from 161, devices stay on their gateways, Show buttons, the MCP key

### Added
- **Show / Hide button beside every password, token and secret box** (device logins, SSO and LDAP secrets, BGP/OSPF keys, backup and Users passwords), so a saved value can be read. The sign-in box has none. One observer in `app.js` adds it to every `input[type=password]`, including ones drawn later.
- **A new gateway made on Topology gets a random gateway key** (32 hex characters) instead of the well-known default, as the daemon's own add already did.
- **The first gateway also makes one MCP key**, `default`, access `ro`, shown once in the usual key window. Only when there are no MCP keys yet. The key is still kept as a hash, so it can be seen only then; Show cannot read it back.

### Changed
- **Ports**: the web GUI listens on **22161** (was 12380), the cluster on **22162** (was 12381). Defaults in the daemon, the example config, `install.sh` (and its firewall hints), README, QUICKSTART, the help panels and the tests. The gateway protocol stays on UDP 12382: it is protocol identity. An existing config that names a port keeps it.
- **Gateways are numbered from 161** (`firstGroupID`; was 100), in the daemon, `--canvas-add`, `--configure` and the Topology form.
- **Monitoring ▸ MCP**: the address under the keys, and the one in the key window and its Claude Code command, is now the first gateway's shared (VIP) address on the GUI port, e.g. `https://192.168.5.24:22161/mcp`, not the node the page was opened on. With no gateway it falls back to the node's address.
- **Configure ▸ Devices**: the Devices table is 50% wider (42 to 63 rem), and its column is **Login**, like the **Logins** card.

### Fixed
- **Devices attached to a gateway on Topology disappeared.** Every save from a Configure page (Settings, Devices, Monitoring, …) rebuilt the gateways from its own fields and left out `devices`, so the next change on any of those pages wiped them. The page now carries each gateway's devices through, less any the Devices table no longer lists. Checked against the old `app.js` with the same mock: the old page saved the gateway without `devices`, the new one with `["sw1"]`.

### Verified
- Linux: `gofmt -l` empty, `go build`, `go vet`, the five cross-builds, `CGO_ENABLED=0 go vet`, `node --check webui/app.js`.
- `go test -race ./...`: the 37 tests that failed before this change (they still test the removed NTP pages and scheduler action `stats_clear`) fail the same way; nothing new fails, apart from `TestBGPOperateAPIAndStatus` once in a full run (it passes alone, three times). `TestApplyCanvasEdit` followed the new first number.
- Chromium (light and dark) against a mocked API: the Devices table 1008 px wide, the column named Login, Show/Hide reading a saved password, the MCP address `https://192.168.5.24:22161/mcp`, a save from Configure ▸ Devices keeping the gateway's devices, a new gateway saved with a random key and the `default` MCP key window.

### Not verified
- No real daemon, PAM sign-in, cluster, device or two-node run (none of this was tried on a live host). The CLI `--canvas-add gateway` does not make an MCP key: it has no way to show it once.
- The 37 old test failures were not fixed.

## [v3] - 2026-11-01 — Devices on the Topology page, per gateway, with health checks

### Added
- **Each gateway has its own devices** (`groups[].devices`, by name, shared by the cluster; checked against `settings.devices`). A device may be on several gateways. The target `gateway:N` picks the devices of gateway N (API, MCP, Monitor ▸ Devices).
- **Device health checks** (`device/health.go`): every node opens a TCP connection to each device's API port every 30 s and asks its facts every 5 minutes (and at once when it comes back). Green answering, amber login or API refused, red unreachable, grey not checked, dashed disabled. On `/api/devices`, in the canvas data, as the alert **Device not answering** (after 3 minutes), and as Monitor ▸ Devices' State column.
- **Topology**: the gateway's devices as squares under the circle, coloured by health, with a tooltip of model, OS, uptime and last answer; drag to reorder. Right-click a device: Facts, Interfaces, Neighbors, Configuration, Show command, Network tools, Edit, Copy device, Remove from this gateway (also the Delete key), Delete device. Right-click the circle: Add device (one from the inventory, or a new one with a new login), Paste device, Ask its devices ▸ Facts / Interfaces / Neighbors (opens Monitor ▸ Devices with the question asked).
- CLI `--canvas-add|--canvas-del|--canvas-move device --group N --device NAME`, devices in `--canvas`; MCP tool `set_gateway_device`.

### Verified
- macOS: `go test -race ./device` (the health monitor against a TLS stub: ok, disabled, unreachable, facts not re-asked early, a wrong password amber with the last facts kept and the password not shown).
- Linux: the five cross-builds, `go vet`, `go test -c` (the new tests compile: gateway device validation and replication, canvas edits, `gateway:N`, the canvas's device squares, MCP `set_gateway_device`).
- Built-in browser against a mocked API: the squares and their colours and tooltips, the device menu, Facts in a popup, Copy device on one gateway and Paste device on another (greyed out where it already is), Add device with a new token login, a rename that follows the device onto both gateways, the Delete key taking it off one gateway only, Delete device everywhere, Show command, Ask its devices handing over to Monitor ▸ Devices. No script errors.
- The help tests' checks in Python: 87 fields covered.

### Not verified
- No test of the daemon ran (Linux only), and nothing against a real daemon or real devices.

## [v2] - 2026-11-01 — The web GUI converted to netdir

### Added
- **Monitor ▸ Devices.** The inventory, and a form that asks the devices a target picks (`all`, a name, `tag:…`, `platform:…`) for facts, interfaces, neighbors, the configuration (with Copy and Download) or one show command. Every device answers on its own row or card, with its time or why it failed. Nothing is polled.
- **Network tools there**: an address box with Ping, Traceroute, Scan, Lookup and Whois, and the same on a device row's right-click. They were on the Statistics page, which is gone; they keep the CLI's `--ping`, `--traceroute`, `--scan`, `--host-lookup` and `--whois` reachable from the GUI.
- **Configure ▸ Devices.** A table of devices (name, platform, address, port, login, tags, certificate check) and a table of logins (user name, password, token; the secrets are password fields and are not copied by Copy row). Options, `ca_pem` and `disabled`, which have no column, are kept from the saved device of the same name.
- Help panels `devices` and `config_devices`.

### Changed
- **The Settings pages save the `settings` block** and read it, instead of `ntp`. The Topology page saves the gateways without any NTP block.
- **Topology**: the gateway circle shows its name and addresses. The NTP server squares are gone, and so are their menus, copy and paste, graphs, the fallback and health-check fields of the gateway form, the AnyName (dnsdir) gateway, the clock and its time-zone picker, and the "used for time" legend. A gateway is red when it runs but this node's MCP and web listener is not serving.
- **Monitor ▸ Gateways**: the NTP column is now Service.
- **Cluster tables**: the clock column and the clock-spread line are gone.
- Monitor ▸ Node and Capture still offer Cluster and the gateways in the Node menu; Statistics did too and is gone.
- The scheduler's new-task form starts with **backup** instead of clearing the statistics.
- The help: the topology panel is rewritten; NTP wording is gone from the other panels. `help_test.go` and `help_fields_test.go` follow the new pages.

### Removed
- Monitor ▸ NTP, Monitor ▸ Statistics, Configure ▸ NTP (five tabs), the self-check card, and their help panels.

### Verified
- **In the built-in browser (Chromium)** against a mocked API (a script that stands in for the daemon and keeps every config the page saves):
  - Every page opens with no script error. The one rejection seen comes from the Anycast pages asking the mock for `/api/bgp`; those pages are unchanged.
  - Topology draws the gateway, its nodes and its anycast pill, and its menus offer only what exists. Editing the gateway saves a config with `settings` and no `ntp` anywhere, keeping the anycast addresses and the node order.
  - Configure ▸ Devices: changing a device's address saves it, keeps the FortiGate's `options.vdom`, the logins and every other shared setting.
  - Monitor ▸ Devices: facts (with a failed device's error across its row), interfaces, configuration (Copy, Download), a refused `reload` shown beside the form, and Ping in its popup.
  - The help panel for Configure ▸ Devices, in light and dark.
- The checks of `help_test.go` and `help_fields_test.go`, run with a Python copy of their logic: 38 panels, 75 labelled fields, all covered.
- `gofmt`, the five Linux cross-builds, `go vet` and `go test -c` for Linux; `go test -race ./device` on macOS.

### Not verified
- **Against a real daemon.** The GUI was only driven against the mock, and none of the daemon's tests ran (no Linux here).
- `node --check` (no Node.js here). The browser parsing the file, and every page running, stand in for it.
- The Anycast pages with real BGP and OSPF answers, and the page at phone width.

## [v1] - 2026-11-01 — MCP Network Director: the first release

netdir is forked from the AnyTime NTP Director v201. The VIP election, anycast with BGP and OSPF, LLDP, clustering, the GUI's sign-in, users, history, certificates, updates, backups and the scheduler are carried over. The NTP serving is removed, and an MCP gateway to switches and firewalls is added.

### Added
- **Managed devices.** The package `source/device/` has a driver interface, the inventory (`settings.devices`) and credentials (`settings.device_credentials`), target selection, and fan-out to 16 devices at a time with a time limit per device. `CheckShow` lets through only read-only commands.
  - `iosxe`: Cisco Catalyst over RESTCONF.
  - `fortios`: FortiGate over the REST API with a token.
- **MCP tools**: `list_devices`, `device_facts`, `device_interfaces`, `device_neighbors`, `device_config` (read-write callers only) and `device_show`.
- **API**: `GET /api/devices` and `GET /api/devices/query`.
- **`source/tools/devprobe`**: the same drivers from any machine, against an inventory file.
- **Gateway health from the web listener** (`health.go`). A node carries a gateway's addresses while its MCP and web listener serves. Anycast addresses are withdrawn, and the canvas turns red, when it does not.

### Changed
- **Name**: MCP Network Director, `netdir`. Binary, paths (`/var/lib/netdir`, `/run/netdir`), group, PAM service, unit, environment (`NETDIR_*`) and metrics (`netdir_*`) are renamed. The wire protocol, its magic and the default gateway key `"ntpdir"` are protocol identity and are unchanged.
- **Shared settings.** The `ntp` block is now `settings` and holds only access lists, devices, SNMP, LLDP, alerts, backups and the schedule. A configuration that still has an `ntp` block is refused with a message saying so. This means the old GUI pages, which still write it, cannot drop the settings in silence.
- **Installer and uninstaller** no longer install or touch chrony.

### Removed
- chrony management, upstream NTP pools and probing, NTP wire handling, fallback servers, per-gateway pools and health checks, client access and rate limits, NTS and leap seconds, the self-check, the node clock, query statistics and server history, the dnsdir piggyback gateway, and the CLI and API for all of these (`--show-ntp`, `--stats`, `--server-stats`, `/api/ntp`, `/api/qstats`, …).
- NTP-only tests. Core tests that used NTP only as a probe were rewritten instead of dropped: cluster join and sync, config validation and round trip, MCP secret hiding (now with device credentials), anycast pause and sharing, canvas colours and edits, history, scheduler and capture.

### Verified
- On macOS (go1.27.3):
  - `gofmt -l .` is empty.
  - `go vet ./device ./tools/...`.
  - `go test -race -count=1 ./device`: drivers against TLS stub devices, wrong password or token, no redirect followed, self-signed certificate refused, fan-out, secret scrubbing, `CheckShow`.
- For Linux: `GOOS=linux CGO_ENABLED=0 go build` for amd64, arm64, arm, 386 and riscv64, `go vet ./...`, and `go test -c` (every test of the daemon compiles).
- `bash -n` on `install.sh`, `uninstall.sh` and `get.sh`.

### Not verified
- **No test of the daemon was run.** The main package is Linux-only and no Linux machine was available, so this release has only been compiled.
- No native build with PAM, no live daemon, no cluster run, no shellcheck, no installer run.
- **The drivers have not met a real Catalyst or FortiGate**, only stubs written from the vendors' documented models.
- **The web GUI is not converted.** It still shows the NTP and Statistics pages and builds an `ntp` block when it saves settings. The daemon refuses that block, so the Settings pages cannot save until the GUI is reworked. `node --check` was not run (no Node.js here).
