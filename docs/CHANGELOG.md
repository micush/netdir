# Changelog

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
