package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A Windows host over OpenSSH (the "OpenSSH Server" optional feature of Windows 10, 11 and Server 2019 or later) and PowerShell.  The
// transport is the Linux driver's (linuxExec: the system ssh, a password through SSH_ASKPASS or a PEM key as the token, host keys
// learned on first use), and what differs is what runs: the script is base64-encoded into one line of PowerShell that decodes and runs it,
// sent to "powershell -Command -" on standard input, so neither cmd.exe's nor PowerShell's quoting, nor cmd.exe's line length, matters.
// A user in the Administrators group gets a full token over OpenSSH, so writes need nothing like sudo; any other user reads what a
// user may read and the answer says so when a change is refused.  The login is "user", "DOMAIN\user" or "user@domain".
//
// Reads are CIM and NetTCPIP cmdlets whose answers are JSON; the host has no LLDP.  Changes are shutdown and no shutdown
// (Disable-NetAdapter, Enable-NetAdapter) and raw lines of PowerShell.  Adapters have no description of their own to set.

func init() { Register("windows", newWindows) }

type windows struct {
	d Device
	t linuxTarget
}

var winUserRE = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@\\-]{0,127}$`)

func newWindows(d Device, c Credential) (Driver, error) {
	if c.Username == "" {
		return nil, fmt.Errorf("device %s: SSH needs a user name (and a password or a private key as the token; with neither the daemon's own keys are tried)", d.Name)
	}
	if strings.HasPrefix(d.Address, "-") || strings.ContainsAny(d.Address, " \t\r\n\x00'\"`$;&|<>\\") || d.Address == "" {
		return nil, fmt.Errorf("device %s: %q is not a host name or an address", d.Name, d.Address)
	}
	if !winUserRE.MatchString(c.Username) {
		return nil, fmt.Errorf("device %s: %q is not a user name", d.Name, c.Username)
	}
	t := linuxTarget{Host: d.Address, Port: d.Port, User: c.Username, Pass: c.Password, Insecure: d.Insecure, Win: true}
	if t.Port == 0 {
		t.Port = 22
	}
	if strings.Contains(c.Token, "PRIVATE KEY") {
		t.Key = c.Token
	}
	return &windows{d: d, t: t}, nil
}

func (w *windows) Close(context.Context) {}

// winInvocation is the command and the standard input that run a PowerShell script on a Windows host.
func winInvocation(script string) (remote, stdin string) {
	b := base64.StdEncoding.EncodeToString([]byte(script))
	stdin = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;try{& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b +
		"'))); exit 0}catch{[Console]::Error.WriteLine($_.Exception.Message); exit 1}\n"
	return "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -", stdin
}

func (w *windows) run(ctx context.Context, op, script string) (string, error) {
	so, se, err := linuxExec(ctx, w.t, script, false)
	if err != nil {
		return so, linuxErr(op, se, err)
	}
	return strings.TrimPrefix(so, "\ufeff"), nil
}

// psJSON parses what ConvertTo-Json printed: an array, or one object when PowerShell unrolled a single element.
func psJSON(out string, v any) error {
	out = strings.TrimSpace(strings.TrimPrefix(out, "\ufeff"))
	if out == "" {
		return nil
	}
	if strings.HasPrefix(out, "{") {
		out = "[" + out + "]"
	}
	return json.Unmarshal([]byte(out), v)
}

func (w *windows) Facts(ctx context.Context) (Facts, error) {
	out, err := w.run(ctx, "facts", `$o=Get-CimInstance Win32_OperatingSystem; $c=Get-CimInstance Win32_ComputerSystem; $b=Get-CimInstance Win32_BIOS
[pscustomobject]@{host=$env:COMPUTERNAME; dns=$c.DNSHostName; domain=$c.Domain; os=$o.Caption; version=$o.Version; build=$o.BuildNumber; up=[int64]((Get-Date)-$o.LastBootUpTime).TotalSeconds; model=$c.Model; vendor=$c.Manufacturer; serial=$b.SerialNumber} | ConvertTo-Json -Compress`)
	if err != nil {
		return Facts{}, err
	}
	var m []map[string]any
	if err := psJSON(out, &m); err != nil || len(m) == 0 {
		return Facts{}, fmt.Errorf("facts: the host's answer is not JSON: %v", err)
	}
	r := m[0]
	host := firstOf(str(r["dns"]), str(r["host"]))
	if d := str(r["domain"]); d != "" && !strings.EqualFold(d, "WORKGROUP") && !strings.Contains(host, ".") && strings.Contains(d, ".") {
		host += "." + d
	}
	return Facts{Hostname: host, Vendor: "Microsoft Windows", Model: strings.TrimSpace(str(r["vendor"]) + " " + str(r["model"])),
		OSVersion: strings.TrimSpace(str(r["os"]) + " " + str(r["version"])), Serial: str(r["serial"]), UptimeS: num(r["up"])}, nil
}

type winAdapter struct {
	Name   string  `json:"name"`
	Desc   string  `json:"desc"`
	Status string  `json:"status"`
	MAC    string  `json:"mac"`
	Speed  int64   `json:"speed"`
	MTU    int64   `json:"mtu"`
	Full   *bool   `json:"full"`
	Media  string  `json:"media"`
	IPs    winStrs `json:"ips"`
	RxB    int64   `json:"rxb"`
	RxU    int64   `json:"rxu"`
	RxM    int64   `json:"rxm"`
	RxD    int64   `json:"rxd"`
	RxE    int64   `json:"rxe"`
	TxB    int64   `json:"txb"`
	TxU    int64   `json:"txu"`
	TxD    int64   `json:"txd"`
	TxE    int64   `json:"txe"`
}

// winStrs is a list PowerShell wrote as a string when it had one element.
type winStrs []string

func (s *winStrs) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = winStrs{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return nil // null
	}
	*s = many
	return nil
}

const winAdapterScript = `$st=@{}; Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object { $st[$_.Name]=$_ }
$ips=@{}; Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { if(-not $ips.ContainsKey([int]$_.InterfaceIndex)){$ips[[int]$_.InterfaceIndex]=@()}; $ips[[int]$_.InterfaceIndex]+=("{0}/{1}" -f $_.IPAddress,$_.PrefixLength) }
$r=@(Get-NetAdapter | ForEach-Object { $s=$st[$_.Name]; $i=[int]$_.ifIndex; [pscustomobject]@{name=$_.Name; desc=$_.InterfaceDescription; status=[string]$_.Status; mac=$_.MacAddress; speed=[int64]$_.Speed; mtu=[int64]$_.MtuSize; full=$_.FullDuplex; media=[string]$_.MediaType; ips=$(if($ips.ContainsKey($i)){$ips[$i]}else{@()}); rxb=[int64]$s.ReceivedBytes; rxu=[int64]$s.ReceivedUnicastPackets; rxm=[int64]$s.ReceivedMulticastPackets; rxd=[int64]$s.ReceivedDiscardedPackets; rxe=[int64]$s.ReceivedPacketErrors; txb=[int64]$s.SentBytes; txu=[int64]$s.SentUnicastPackets; txd=[int64]$s.OutboundDiscardedPackets; txe=[int64]$s.OutboundPacketErrors} })
ConvertTo-Json -InputObject $r -Compress -Depth 4`

func (w *windows) adapters(ctx context.Context) ([]winAdapter, error) {
	out, err := w.run(ctx, "interfaces", winAdapterScript)
	if err != nil {
		return nil, err
	}
	var as []winAdapter
	if err := psJSON(out, &as); err != nil {
		return nil, fmt.Errorf("interfaces: the host's answer is not JSON: %v", err)
	}
	return as, nil
}

func (a winAdapter) iface() Interface {
	i := Interface{Name: a.Name, Description: a.Desc, AdminUp: boolp(a.Status != "Disabled"), OperUp: boolp(a.Status == "Up"),
		MAC: strings.ToLower(strings.ReplaceAll(a.MAC, "-", ":")), Addresses: a.IPs}
	if a.Speed > 0 && a.Speed < 1<<62 {
		i.SpeedMbps = a.Speed / 1_000_000
	}
	return i
}

func (w *windows) Interfaces(ctx context.Context) ([]Interface, error) {
	as, err := w.adapters(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, len(as))
	for i, a := range as {
		out[i] = a.iface()
	}
	return out, nil
}

// Ports implements Porter.
func (w *windows) Ports(ctx context.Context) ([]Port, error) {
	as, err := w.adapters(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Port, len(as))
	for i, a := range as {
		p := Port{Interface: a.iface(), Type: a.Media, MTU: a.MTU}
		if a.Full != nil {
			p.Duplex = map[bool]string{true: "full", false: "half"}[*a.Full]
		}
		p.Counters = Counters{InOctets: a.RxB, InUnicast: a.RxU, InMulticast: a.RxM, InPackets: a.RxU + a.RxM, InDiscards: a.RxD, InErrors: a.RxE,
			OutOctets: a.TxB, OutUnicast: a.TxU, OutPackets: a.TxU, OutDiscards: a.TxD, OutErrors: a.TxE}
		out[i] = p
	}
	return out, nil
}

// Neighbors: Windows does not speak LLDP unless a third-party agent is installed.
func (w *windows) Neighbors(context.Context) ([]Neighbor, error) {
	return nil, fmt.Errorf("neighbors: %w (Windows has no LLDP of its own)", ErrUnsupported)
}

// Routes implements Router.
func (w *windows) Routes(ctx context.Context) ([]Route, error) {
	out, err := w.run(ctx, "routes", `$r=@(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne $null } | ForEach-Object { [pscustomobject]@{dst=$_.DestinationPrefix; gw=$_.NextHop; dev=$_.InterfaceAlias; metric=[int64]$_.RouteMetric; proto=[string]$_.Protocol} })
ConvertTo-Json -InputObject $r -Compress`)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := psJSON(out, &rows); err != nil {
		return nil, fmt.Errorf("routes: the host's answer is not JSON: %v", err)
	}
	var rs []Route
	for _, m := range rows {
		gw := str(m["gw"])
		if gw == "0.0.0.0" || gw == "::" {
			gw = "" // on-link
		}
		rs = append(rs, Route{Protocol: str(m["proto"]), Prefix: str(m["dst"]), NextHop: gw, Interface: str(m["dev"]), Metric: num(m["metric"]), Raw: m})
	}
	return rs, nil
}

func (w *windows) Routing(ctx context.Context) (Routing, error) {
	rs, err := w.Routes(ctx)
	if err != nil {
		return Routing{}, err
	}
	return Routing{Protocols: map[string]any{"routes": rs}, Unavailable: map[string]string{"bgp": "a Windows host has no routing protocols unless Routing and Remote Access is set up; show routes lists the table"}}, nil
}

// Resources implements Resourcer.
func (w *windows) Resources(ctx context.Context) (Resources, error) {
	out, err := w.run(ctx, "resources", `$o=Get-CimInstance Win32_OperatingSystem
$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$d=@(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { [pscustomobject]@{name=$_.DeviceID; size=[int64]$_.Size; free=[int64]$_.FreeSpace} })
[pscustomobject]@{cpu=[double]$cpu; memtotal=[int64]$o.TotalVisibleMemorySize*1024; memfree=[int64]$o.FreePhysicalMemory*1024; swaptotal=[int64]$o.SizeStoredInPagingFiles*1024; swapfree=[int64]$o.FreeSpaceInPagingFiles*1024; disks=$d} | ConvertTo-Json -Compress -Depth 4`)
	if err != nil {
		return Resources{}, err
	}
	var m []map[string]any
	if err := psJSON(out, &m); err != nil || len(m) == 0 {
		return Resources{}, fmt.Errorf("resources: the host's answer is not JSON: %v", err)
	}
	r0 := m[0]
	var r Resources
	cpu := flt(r0["cpu"])
	r.CPU = &CPU{Now: cpu, OneMin: cpu}
	mem := func(name string, tot, free int64) {
		if tot > 0 {
			r.Memory = append(r.Memory, Memory{Name: name, Total: tot, Used: tot - free, Free: free, UsedPercent: float64(tot-free) / float64(tot) * 100})
		}
	}
	mem("Mem", num(r0["memtotal"]), num(r0["memfree"]))
	mem("Swap", num(r0["swaptotal"]), num(r0["swapfree"]))
	for _, d := range rows(r0["disks"]) {
		size, free := num(d["size"]), num(d["free"])
		s := Storage{Name: str(d["name"]), Size: size, Free: free}
		if size > 0 {
			s.UsedPercent = float64(size-free) / float64(size) * 100
		}
		r.Storage = append(r.Storage, s)
	}
	r.Details = Routing{Protocols: map[string]any{}}
	return r, nil
}

// Config is the host's network: ipconfig, the routing table, DNS client settings, the firewall profiles and the enabled inbound rules.
func (w *windows) Config(ctx context.Context) (string, error) {
	out, err := w.run(ctx, "configuration", `"### ipconfig"; ipconfig /all | Out-String -Width 300
"### routes"; route print | Out-String -Width 300
"### dns"; Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Format-Table InterfaceAlias,AddressFamily,ServerAddresses -AutoSize | Out-String -Width 300
"### firewall profiles"; Get-NetFirewallProfile -ErrorAction SilentlyContinue | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction -AutoSize | Out-String -Width 300
"### firewall inbound rules (enabled)"; Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue | Select-Object -First 500 | Format-Table DisplayName,Action,Profile -AutoSize | Out-String -Width 300`)
	if err != nil {
		return "", err
	}
	const max = 1 << 20
	if len(out) > max {
		out = out[:max] + "\n… cut at 1 MB\n"
	}
	return out, nil
}

var (
	winNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_ .:()#/-]{0,127}$`)
	winLogs   = map[string]bool{"system": true, "application": true, "security": true, "setup": true}
)

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// winShow turns "show ..." into the PowerShell of a fixed list; every command's output is text of at most 200 columns.
func winShow(f []string) (string, error) {
	usage := errors.New("show ip | links | routes | neighbors | ports | services | service NAME | processes | eventlog [N] | log NAME [N] | disk | memory | cpu | version | firewall | dns | time | users | updates | shares")
	if len(f) < 2 {
		return "", usage
	}
	n := func(i, def, max int) int {
		if len(f) > i {
			if v, err := strconv.Atoi(f[i]); err == nil && v > 0 {
				return min(v, max)
			}
		}
		return def
	}
	tbl := func(cmd string) string { return cmd + " | Out-String -Width 200" }
	switch strings.ToLower(f[1]) {
	case "ip", "addresses":
		return tbl("Get-NetIPAddress | Sort-Object InterfaceAlias | Format-Table InterfaceAlias,AddressFamily,IPAddress,PrefixLength,PrefixOrigin -AutoSize"), nil
	case "links":
		return tbl("Get-NetAdapter | Format-Table Name,InterfaceDescription,Status,MacAddress,LinkSpeed -AutoSize"), nil
	case "routes":
		return tbl("Get-NetRoute | Sort-Object DestinationPrefix | Format-Table DestinationPrefix,NextHop,InterfaceAlias,RouteMetric -AutoSize"), nil
	case "neighbors", "arp":
		return tbl("Get-NetNeighbor | Where-Object State -ne 'Unreachable' | Format-Table IPAddress,LinkLayerAddress,State,InterfaceAlias -AutoSize"), nil
	case "ports":
		return tbl("Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize"), nil
	case "services":
		return tbl("Get-Service | Where-Object Status -eq 'Running' | Format-Table Name,DisplayName -AutoSize"), nil
	case "service":
		if len(f) < 3 || !winNameRE.MatchString(strings.Join(f[2:], " ")) {
			return "", errors.New("show service NAME")
		}
		return tbl("Get-Service -Name " + psQuote(strings.Join(f[2:], " ")) + " | Format-List Name,DisplayName,Status,StartType,ServiceName"), nil
	case "processes":
		return tbl("Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table Id,ProcessName,CPU,WS -AutoSize"), nil
	case "eventlog":
		return tbl(fmt.Sprintf("Get-WinEvent -LogName System -MaxEvents %d | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,@{n='Message';e={($_.Message -split \"`n\")[0]}} | Format-Table -Wrap -AutoSize", n(2, 50, 300))), nil
	case "log":
		if len(f) < 3 || !winLogs[strings.ToLower(f[2])] {
			return "", errors.New("show log System|Application|Security|Setup [N]")
		}
		return tbl(fmt.Sprintf("Get-WinEvent -LogName %s -MaxEvents %d | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,@{n='Message';e={($_.Message -split \"`n\")[0]}} | Format-Table -Wrap -AutoSize", psQuote(f[2]), n(3, 50, 300))), nil
	case "disk":
		return tbl("Get-Volume | Format-Table DriveLetter,FileSystemLabel,FileSystem,@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}} -AutoSize"), nil
	case "memory":
		return tbl("Get-CimInstance Win32_OperatingSystem | Format-List @{n='TotalMB';e={[int]($_.TotalVisibleMemorySize/1KB)}},@{n='FreeMB';e={[int]($_.FreePhysicalMemory/1KB)}}"), nil
	case "cpu":
		return tbl("Get-CimInstance Win32_Processor | Format-List Name,NumberOfCores,NumberOfLogicalProcessors,LoadPercentage"), nil
	case "version":
		return tbl("Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime"), nil
	case "firewall":
		return tbl("Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction -AutoSize"), nil
	case "dns":
		return tbl("Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses -AutoSize"), nil
	case "time":
		return "Get-Date -Format o; w32tm /query /status 2>&1 | Out-String", nil
	case "users":
		return "query user 2>&1 | Out-String", nil
	case "updates":
		return tbl("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 | Format-Table HotFixID,Description,InstalledOn -AutoSize"), nil
	case "shares":
		return tbl("Get-SmbShare | Format-Table Name,Path,Description -AutoSize"), nil
	}
	return "", usage
}

// Show runs one of the fixed read commands and applies the filters CheckShow allows.
func (w *windows) Show(ctx context.Context, cmd string) (string, error) {
	cmd, err := CheckShow(cmd)
	if err != nil {
		return "", err
	}
	head, filters, _ := strings.Cut(cmd, "|")
	script, err := winShow(strings.Fields(head))
	if err != nil {
		return "", err
	}
	out, err := w.run(ctx, "show", script)
	if err != nil && out == "" {
		return "", err
	}
	out = strings.ReplaceAll(out, "\r\n", "\n")
	if filters != "" {
		out = linuxFilter(out, "|"+filters)
	}
	return RedactText(out), nil
}

// ── changes ──

func winLines(plan []portPlan) ([]string, error) {
	var out []string
	for _, p := range plan {
		if !winNameRE.MatchString(p.Port) {
			return nil, fmt.Errorf("%q is not an adapter name", p.Port)
		}
		if p.Description != nil {
			return nil, errors.New("a Windows adapter has no description to set")
		}
		if p.Down != nil {
			verb := map[bool]string{true: "Disable-NetAdapter", false: "Enable-NetAdapter"}[*p.Down]
			out = append(out, verb+" -Name "+psQuote(p.Port)+" -Confirm:$false")
		}
	}
	return out, nil
}

// Change implements Changer: shutdown and no shutdown.  An adapter name has spaces ("Ethernet 2") and the port grammar does not, so a
// name typed without them (ethernet2, Ethernet2) is matched to the host's own.
func (w *windows) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	switch c.Action {
	case ActClearCounters:
		return ChangeResult{}, errors.New("a Windows adapter's counters cannot be cleared")
	case ActDescription, ActClearDescription:
		return ChangeResult{}, errors.New("a Windows adapter has no description to set (its name can be changed with device_change_raw: Rename-NetAdapter)")
	}
	if as, err := w.adapters(ctx); err == nil {
		byKey := map[string][]string{}
		have := map[string]bool{}
		for _, a := range as {
			have[a.Name] = true
			k := strings.ToLower(strings.ReplaceAll(a.Name, " ", ""))
			byKey[k] = append(byKey[k], a.Name)
		}
		ports := append([]string(nil), c.Ports...)
		for i, p := range ports {
			if have[p] {
				continue
			}
			if hit := byKey[strings.ToLower(strings.ReplaceAll(p, " ", ""))]; len(hit) == 1 {
				ports[i] = hit[0]
			} else if len(hit) > 1 {
				sort.Strings(hit)
				return ChangeResult{}, fmt.Errorf("say which adapter: %s is %s; nothing was changed", p, strings.Join(hit, " or "))
			}
		}
		c.Ports = ports
	}
	if err := keepManagement(ctx, w, w.d, c); err != nil {
		return ChangeResult{}, err
	}
	return runChange(ctx, ifaceStore{drv: w, rc: w, lines: winLines}, c, dry)
}

var (
	winRawDeny = regexp.MustCompile(`^(?:restart-computer|stop-computer|shutdown|format-volume|clear-disk|initialize-disk|remove-partition|new-localuser|set-localuser|remove-localuser|add-localgroupmember|net\s+user|net\s+localgroup|set-netfirewallprofile\s+.*-enabled\s+false|remove-item\s+.*-recurse.*\s[a-z]:\\\s*$)`)
	winPowerRE = regexp.MustCompile(`^(?:restart-computer|stop-computer|shutdown|wmic\s+os\s+.*reboot)`)
)

// RawChange implements RawChanger: lines of PowerShell, run as one script with $ErrorActionPreference = 'Stop', so the first line that
// fails ends the run.  Windows has no transaction: the result says what ran and nothing is undone.
func (w *windows) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if r.Method != "" || r.Path != "" || r.Body != "" {
		return res, errors.New("method, path and body: this platform is changed with lines of PowerShell")
	}
	lines, err := checkLines(r, winRawDeny)
	if err != nil {
		return res, err
	}
	if dry {
		res.Note = fmt.Sprintf("would run %d line(s) of PowerShell in order, stopping at the first that fails; nothing was run. A Windows host has no undo.", len(lines))
		return res, nil
	}
	script := "$ErrorActionPreference='Stop'\n" + strings.Join(lines, "\n") + "\n"
	so, se, err := linuxExec(ctx, w.t, script, false)
	res.Answer = rawTrunc([]byte(strings.TrimSpace(so + "\n" + se)))
	if err != nil {
		for _, ln := range lines {
			if winPowerRE.MatchString(strings.ToLower(ln)) && sshEnded(err) {
				res.Applied, res.Note = true, "the connection ended, as it does when the host restarts or powers off"
				return res, nil
			}
		}
		return res, fmt.Errorf("%w; lines before the failing one have run and are not undone", linuxErr("change", se, err))
	}
	res.Applied = true
	if r.Save {
		res.Note = "nothing to save: a Windows host keeps what a line changed"
	}
	return res, nil
}
