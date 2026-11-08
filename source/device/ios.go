package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Cisco IOS (the classic software of Catalyst 2960, 3560, 3750, 3850 before IOS-XE, ISR and the like) has no REST API; the
// driver reads it over SNMP, v2c or v3, UDP port 161 (Port 0).  It reads: facts (SNMPv2-MIB, ENTITY-MIB), interfaces and
// ports (IF-MIB, IP-MIB), LLDP and CDP neighbors (LLDP-MIB, CISCO-CDP-MIB), the routing table (IP-FORWARD-MIB) and any
// subtree by its OID.  It does not read the running configuration or run CLI commands: SNMP has no way to, and an SSH
// transport does not exist in this program.
//
// The login:
//
//	v2c   the community is the credential's Token (or its Password) with no user name
//	v3    Username, and Password as the authentication passphrase; Token is the privacy passphrase (without one, the
//	      authentication passphrase is used for privacy when the option "priv" asks for it, and the level is authNoPriv when
//	      it does not).  Options: "auth" md5, sha (the default), sha224, sha256, sha384 or sha512; "priv" aes (the default
//	      with a privacy passphrase), des or none; "snmp_version" 2c or 3 (3 when there is a user name).
//
// Not tried against a real device: the OIDs are those of the standard and Cisco MIBs.

func init() { Register("ios", newIOS) }

type ios struct {
	d Device
	c *snmpConn
}

func newIOS(d Device, c Credential) (Driver, error) {
	s := newSNMPConn(hostPort(d, 161))
	ver := strings.ToLower(strings.TrimSpace(d.Options["snmp_version"]))
	if ver == "" {
		ver = "2c"
		if c.Username != "" {
			ver = "3"
		}
	}
	switch ver {
	case "2c", "2":
		comm := c.Token
		if comm == "" {
			comm = c.Password
		}
		if comm == "" {
			return nil, fmt.Errorf("device %s: SNMP v2c needs the community as the credential's token (or password)", d.Name)
		}
		s.version, s.comm = 1, comm
	case "3":
		if c.Username == "" {
			return nil, fmt.Errorf("device %s: SNMP v3 needs a user name", d.Name)
		}
		u := &snmpUSM{user: c.Username}
		if c.Password != "" {
			name := strings.ToLower(strings.TrimSpace(d.Options["auth"]))
			if name == "" {
				name = "sha"
			}
			a, ok := snmpAuths[name]
			if !ok {
				return nil, fmt.Errorf("device %s: option auth %q is none of md5, sha, sha224, sha256, sha384, sha512", d.Name, name)
			}
			if len(c.Password) < 8 {
				return nil, fmt.Errorf("device %s: an SNMP v3 passphrase is at least 8 characters", d.Name)
			}
			u.auth, u.authPass = &a, c.Password
			priv := strings.ToLower(strings.TrimSpace(d.Options["priv"]))
			switch {
			case priv == "" && c.Token != "":
				priv = "aes"
			case priv == "" || priv == "none":
				priv = ""
			case priv != "aes" && priv != "des":
				return nil, fmt.Errorf("device %s: option priv %q is none of aes, des, none", d.Name, priv)
			}
			u.priv, u.privPass = priv, c.Token
			if priv != "" && c.Token != "" && len(c.Token) < 8 {
				return nil, fmt.Errorf("device %s: an SNMP v3 passphrase is at least 8 characters", d.Name)
			}
		}
		s.version, s.usm = 3, u
	default:
		return nil, fmt.Errorf("device %s: option snmp_version %q is 2c or 3", d.Name, ver)
	}
	return &ios{d: d, c: s}, nil
}

func (i *ios) Close(context.Context) { i.c.close() }

const (
	oSysDescr   = "1.3.6.1.2.1.1.1.0"
	oSysUp      = "1.3.6.1.2.1.1.3.0"
	oSysName    = "1.3.6.1.2.1.1.5.0"
	oEntClass   = "1.3.6.1.2.1.47.1.1.1.1.5"
	oEntModel   = "1.3.6.1.2.1.47.1.1.1.1.13"
	oEntSerial  = "1.3.6.1.2.1.47.1.1.1.1.11"
	oIfDescr    = "1.3.6.1.2.1.2.2.1.2"
	oIfType     = "1.3.6.1.2.1.2.2.1.3"
	oIfMTU      = "1.3.6.1.2.1.2.2.1.4"
	oIfMAC      = "1.3.6.1.2.1.2.2.1.6"
	oIfAdmin    = "1.3.6.1.2.1.2.2.1.7"
	oIfOper     = "1.3.6.1.2.1.2.2.1.8"
	oIfInDisc   = "1.3.6.1.2.1.2.2.1.13"
	oIfInErr    = "1.3.6.1.2.1.2.2.1.14"
	oIfOutDisc  = "1.3.6.1.2.1.2.2.1.19"
	oIfOutErr   = "1.3.6.1.2.1.2.2.1.20"
	oIfName     = "1.3.6.1.2.1.31.1.1.1.1"
	oIfHCInOct  = "1.3.6.1.2.1.31.1.1.1.6"
	oIfHCInUc   = "1.3.6.1.2.1.31.1.1.1.7"
	oIfHCInMc   = "1.3.6.1.2.1.31.1.1.1.8"
	oIfHCInBc   = "1.3.6.1.2.1.31.1.1.1.9"
	oIfHCOutOct = "1.3.6.1.2.1.31.1.1.1.10"
	oIfHCOutUc  = "1.3.6.1.2.1.31.1.1.1.11"
	oIfHCOutMc  = "1.3.6.1.2.1.31.1.1.1.12"
	oIfHCOutBc  = "1.3.6.1.2.1.31.1.1.1.13"
	oIfHighSpd  = "1.3.6.1.2.1.31.1.1.1.15"
	oIfAlias    = "1.3.6.1.2.1.31.1.1.1.18"
	oIPAddr     = "1.3.6.1.2.1.4.20.1.1"
	oIPIfIdx    = "1.3.6.1.2.1.4.20.1.2"
	oIPMask     = "1.3.6.1.2.1.4.20.1.3"
	oLldpLocDsc = "1.0.8802.1.1.2.1.3.7.1.4"
	oLldpRemID  = "1.0.8802.1.1.2.1.4.1.1.7"
	oLldpRemDsc = "1.0.8802.1.1.2.1.4.1.1.8"
	oLldpRemSys = "1.0.8802.1.1.2.1.4.1.1.9"
	oLldpRemSD  = "1.0.8802.1.1.2.1.4.1.1.10"
	oCdpAddr    = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	oCdpDevID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	oCdpPort    = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	oCdpPlat    = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
	oRtDest     = "1.3.6.1.2.1.4.24.4.1.1"
	oRtIf       = "1.3.6.1.2.1.4.24.4.1.5"
	oRtProto    = "1.3.6.1.2.1.4.24.4.1.7"
	oRtMetric   = "1.3.6.1.2.1.4.24.4.1.11"
	oRtNext     = "1.3.6.1.2.1.4.24.4.1.4"
	oRtMask     = "1.3.6.1.2.1.4.24.4.1.2"
)

var iosVersionRE = regexp.MustCompile(`Version\s+([^,\s]+)`)

func (i *ios) Facts(ctx context.Context) (Facts, error) {
	f := Facts{Vendor: "Cisco"}
	vs, err := i.c.get(ctx, oSysDescr, oSysUp, oSysName)
	if err != nil {
		return f, err
	}
	for _, v := range vs {
		switch v.OID {
		case oSysDescr:
			d := v.Text()
			if m := iosVersionRE.FindStringSubmatch(d); m != nil {
				f.OSVersion = m[1]
			}
			if k := strings.Index(d, "("); k >= 0 {
				if e := strings.Index(d[k:], ")"); e > 1 {
					f.Model = d[k+1 : k+e]
				}
			}
		case oSysUp:
			f.UptimeS = v.Int / 100
		case oSysName:
			f.Hostname = v.Text()
		}
	}
	if f.Hostname == "" {
		f.Hostname = i.d.Name
	}
	// the chassis, as ENTITY-MIB lists it, names the model and the serial number
	if cls, err := i.c.column(ctx, oEntClass); err == nil {
		idx := ""
		for k, v := range cls {
			if v.Int == 3 && (idx == "" || numLess(k, idx)) {
				idx = k
			}
		}
		if idx != "" {
			if r, err := i.c.get(ctx, oEntModel+"."+idx, oEntSerial+"."+idx); err == nil {
				for _, v := range r {
					if v.End() {
						continue
					}
					switch v.OID {
					case oEntModel + "." + idx:
						if t := strings.TrimSpace(v.Text()); t != "" {
							f.Model = t
						}
					case oEntSerial + "." + idx:
						f.Serial = strings.TrimSpace(v.Text())
					}
				}
			}
		}
	}
	return f, nil
}

func numLess(a, b string) bool {
	x, e1 := strconv.Atoi(a)
	y, e2 := strconv.Atoi(b)
	if e1 == nil && e2 == nil {
		return x < y
	}
	return a < b
}

func (i *ios) Interfaces(ctx context.Context) ([]Interface, error) {
	ps, err := i.ports(ctx, false)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, len(ps))
	for k, p := range ps {
		out[k] = p.Interface
	}
	return out, nil
}

func (i *ios) Ports(ctx context.Context) ([]Port, error) { return i.ports(ctx, true) }

var ifTypes = map[int64]string{1: "other", 6: "ethernet", 18: "ds1", 23: "ppp", 24: "loopback", 53: "virtual", 131: "tunnel", 135: "vlan", 136: "vlan", 161: "lag", 117: "gigabit-ethernet", 209: "bridge", 150: "mpls", 142: "ip-forward"}

func (i *ios) ports(ctx context.Context, counters bool) ([]Port, error) {
	descr, err := i.c.column(ctx, oIfDescr)
	if err != nil {
		return nil, err
	}
	col := func(o string) map[string]snmpVar { m, _ := i.c.column(ctx, o); return m }
	names, alias, admin, oper, mac, hs := col(oIfName), col(oIfAlias), col(oIfAdmin), col(oIfOper), col(oIfMAC), col(oIfHighSpd)
	var types, mtu map[string]snmpVar
	if counters {
		types, mtu = col(oIfType), col(oIfMTU)
	}
	addrs := map[string][]string{}
	if ips, err := i.c.column(ctx, oIPAddr); err == nil {
		idx, mask := col(oIPIfIdx), col(oIPMask)
		for k, v := range ips {
			ifx, m := idx[k], mask[k]
			bits := ""
			if len(m.Bytes) == 4 {
				ones, _ := net.IPMask(m.Bytes).Size()
				bits = "/" + strconv.Itoa(ones)
			}
			addrs[strconv.FormatInt(ifx.Int, 10)] = append(addrs[strconv.FormatInt(ifx.Int, 10)], v.Text()+bits)
		}
	}
	var cnt map[string]map[string]snmpVar
	if counters {
		cnt = map[string]map[string]snmpVar{}
		for n, o := range map[string]string{"in_octets": oIfHCInOct, "in_unicast": oIfHCInUc, "in_multicast": oIfHCInMc, "in_broadcast": oIfHCInBc,
			"out_octets": oIfHCOutOct, "out_unicast": oIfHCOutUc, "out_multicast": oIfHCOutMc, "out_broadcast": oIfHCOutBc,
			"in_discards": oIfInDisc, "in_errors": oIfInErr, "out_discards": oIfOutDisc, "out_errors": oIfOutErr} {
			cnt[n] = col(o)
		}
	}
	keys := make([]string, 0, len(descr))
	for k := range descr {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return numLess(keys[a], keys[b]) })
	out := make([]Port, 0, len(keys))
	for _, k := range keys {
		var p Port
		p.Name = names[k].Text()
		if p.Name == "" {
			p.Name = descr[k].Text()
		}
		p.Description = alias[k].Text()
		if v, ok := admin[k]; ok {
			p.AdminUp = boolp(v.Int == 1)
		}
		if v, ok := oper[k]; ok {
			p.OperUp = boolp(v.Int == 1)
		}
		p.SpeedMbps = hs[k].Int
		if m := mac[k].Bytes; len(m) == 6 {
			p.MAC = net.HardwareAddr(m).String()
		}
		p.Addresses = addrs[k]
		if counters {
			p.Type = ifTypes[types[k].Int]
			if p.Type == "" && types[k].Int != 0 {
				p.Type = "type-" + strconv.FormatInt(types[k].Int, 10)
			}
			p.MTU = mtu[k].Int
			c := &p.Counters
			c.InOctets, c.InUnicast, c.InMulticast, c.InBroadcast = cnt["in_octets"][k].Int, cnt["in_unicast"][k].Int, cnt["in_multicast"][k].Int, cnt["in_broadcast"][k].Int
			c.OutOctets, c.OutUnicast, c.OutMulticast, c.OutBroadcast = cnt["out_octets"][k].Int, cnt["out_unicast"][k].Int, cnt["out_multicast"][k].Int, cnt["out_broadcast"][k].Int
			c.InDiscards, c.InErrors, c.OutDiscards, c.OutErrors = cnt["in_discards"][k].Int, cnt["in_errors"][k].Int, cnt["out_discards"][k].Int, cnt["out_errors"][k].Int
			c.InPackets = c.InUnicast + c.InMulticast + c.InBroadcast
			c.OutPackets = c.OutUnicast + c.OutMulticast + c.OutBroadcast
			p.Properties = map[string]any{"if_index": k}
		}
		out = append(out, p)
	}
	return out, nil
}

// Neighbors reads LLDP (index timeMark.localPortNum.remIndex) and CDP (index ifIndex.deviceIndex).
func (i *ios) Neighbors(ctx context.Context) ([]Neighbor, error) {
	var out []Neighbor
	names, _ := i.c.column(ctx, oIfName)
	locDesc, _ := i.c.column(ctx, oLldpLocDsc)
	sys, err1 := i.c.column(ctx, oLldpRemSys)
	port, _ := i.c.column(ctx, oLldpRemID)
	pdesc, _ := i.c.column(ctx, oLldpRemDsc)
	sdesc, _ := i.c.column(ctx, oLldpRemSD)
	keys := make([]string, 0, len(sys)+len(port))
	seen := map[string]bool{}
	for k := range port {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range sys {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys { // timeMark.localPortNum.remIndex
		parts := strings.Split(k, ".")
		local := ""
		if len(parts) >= 3 {
			local = parts[1]
		}
		n := Neighbor{Protocol: "lldp", LocalPort: local, RemoteName: sys[k].Text(), RemotePort: port[k].Text(), RemoteDesc: sdesc[k].Text()}
		if d := pdesc[k].Text(); d != "" && (n.RemotePort == "" || !printable(port[k].Bytes)) {
			n.RemotePort = d
		}
		if l := locDesc[local].Text(); l != "" {
			n.LocalPort = l
		} else if nm := names[local].Text(); nm != "" {
			n.LocalPort = nm
		}
		out = append(out, n)
	}
	cdpDev, err2 := i.c.column(ctx, oCdpDevID)
	if len(cdpDev) > 0 {
		cport, caddr, cplat := mustCol(i.c.column(ctx, oCdpPort)), mustCol(i.c.column(ctx, oCdpAddr)), mustCol(i.c.column(ctx, oCdpPlat))
		ck := make([]string, 0, len(cdpDev))
		for k := range cdpDev {
			ck = append(ck, k)
		}
		sort.Strings(ck)
		for _, k := range ck { // ifIndex.deviceIndex
			ifx, _, _ := strings.Cut(k, ".")
			n := Neighbor{Protocol: "cdp", LocalPort: names[ifx].Text(), RemoteName: cdpDev[k].Text(), RemotePort: cport[k].Text(), RemoteDesc: cplat[k].Text()}
			if n.LocalPort == "" {
				n.LocalPort = ifx
			}
			if a := caddr[k].Bytes; len(a) == 4 {
				n.RemoteAddr = net.IP(a).String()
			}
			out = append(out, n)
		}
	}
	if len(out) == 0 && err1 != nil && err2 != nil {
		return nil, err1
	}
	return out, nil
}

func mustCol(m map[string]snmpVar, _ error) map[string]snmpVar { return m }

var rtProtos = map[int64]string{1: "other", 2: "local", 3: "static", 4: "icmp", 5: "egp", 6: "ggp", 7: "hello", 8: "rip", 9: "is-is", 10: "es-is", 11: "igrp", 12: "bbn", 13: "ospf", 14: "bgp", 15: "idpr", 16: "eigrp"}

func (i *ios) Routes(ctx context.Context) ([]Route, error) {
	dest, err := i.c.column(ctx, oRtDest)
	if err != nil && len(dest) == 0 {
		return nil, err
	}
	mask, ifx, proto, metric, nh := mustCol(i.c.column(ctx, oRtMask)), mustCol(i.c.column(ctx, oRtIf)), mustCol(i.c.column(ctx, oRtProto)), mustCol(i.c.column(ctx, oRtMetric)), mustCol(i.c.column(ctx, oRtNext))
	names, _ := i.c.column(ctx, oIfName)
	keys := make([]string, 0, len(dest))
	for k := range dest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Route, 0, len(keys))
	for _, k := range keys {
		r := Route{Protocol: rtProtos[proto[k].Int], Metric: metric[k].Int, Interface: names[strconv.FormatInt(ifx[k].Int, 10)].Text()}
		if m := mask[k].Bytes; len(m) == 4 && len(dest[k].Bytes) == 4 {
			ones, _ := net.IPMask(m).Size()
			r.Prefix = net.IP(dest[k].Bytes).String() + "/" + strconv.Itoa(ones)
		} else {
			r.Prefix = dest[k].Text()
		}
		if a := nh[k].Bytes; len(a) == 4 && !net.IP(a).IsUnspecified() {
			r.NextHop = net.IP(a).String()
		}
		out = append(out, r)
	}
	return out, nil
}

func (i *ios) Routing(context.Context) (Routing, error) { return Routing{}, ErrUnsupported }

func (i *ios) Config(context.Context) (string, error) {
	return "", errors.New("classic Cisco IOS is read over SNMP, which cannot hand over the running configuration")
}

// snmpDenied are subtrees never read: SNMP's own users and communities, and the Cisco MIBs that copy and change configuration.
var snmpDenied = []string{"1.3.6.1.6.3", "1.3.6.1.4.1.9.9.96", "1.3.6.1.4.1.9.9.43", "1.3.6.1.4.1.9.9.95"}

func snmpOIDDenied(o string) bool {
	for _, d := range snmpDenied {
		if o == d || strings.HasPrefix(o, d+".") {
			return true
		}
	}
	return false
}

var oidRE = regexp.MustCompile(`^\.?[0-2](\.\d{1,9}){2,40}$`)

func (i *ios) walkText(ctx context.Context, oid string) ([]snmpVar, error) {
	oid = strings.TrimPrefix(oid, ".")
	if !oidRE.MatchString("." + oid) {
		return nil, errors.New("oid: numbers separated by dots, for example 1.3.6.1.2.1.1 (names are not looked up)")
	}
	if snmpOIDDenied(oid) {
		return nil, errors.New("oid: SNMP users and communities and the configuration-copy MIBs are not read")
	}
	vs, err := i.c.walk(ctx, oid, 500)
	if err == nil && len(vs) == 0 { // a single instance
		vs, err = i.c.get(ctx, oid)
	}
	out := vs[:0]
	for _, v := range vs {
		if !v.End() && !snmpOIDDenied(v.OID) {
			out = append(out, v)
		}
	}
	return out, err
}

func (i *ios) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show oid <OID>   reads a subtree of the SNMP tree (500 variables at most), for example: show oid 1.3.6.1.2.1.1")
	f := strings.Fields(cmd)
	if len(f) != 3 || !strings.EqualFold(f[0], "show") || !strings.EqualFold(f[1], "oid") {
		return "", usage
	}
	vs, err := i.walkText(ctx, f[2])
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&b, "%s = %s\n", v.OID, v.Text())
	}
	return RedactText(b.String()), nil
}

func (i *ios) APIGet(ctx context.Context, path string) (any, bool, error) {
	oid, ok := strings.CutPrefix(path, "/oid/")
	if !ok {
		return nil, false, errors.New("path: /oid/<numeric OID>, for example /oid/1.3.6.1.2.1.1 (see device_api_catalog)")
	}
	vs, err := i.walkText(ctx, oid)
	if err != nil {
		return nil, false, err
	}
	rows := make([]map[string]any, len(vs))
	for k, v := range vs {
		rows[k] = map[string]any{"oid": v.OID, "value": v.Text()}
	}
	b, _ := json.Marshal(map[string]any{"oid": strings.TrimPrefix(oid, "."), "variables": rows})
	var v any
	_ = json.Unmarshal(b, &v)
	return Redact(v), false, nil
}

func (i *ios) APICatalog(context.Context) (any, error) {
	return map[string]any{
		"how": "GET /oid/<numeric OID>: the subtree below an OID is walked over SNMP (500 variables at most). SNMP users and communities and the configuration-copy MIBs are not read.",
		"examples": []string{"/oid/1.3.6.1.2.1.1 (system)", "/oid/1.3.6.1.2.1.2.2 (interfaces)", "/oid/1.3.6.1.2.1.47.1.1.1 (entities)",
			"/oid/1.0.8802.1.1.2.1.4 (LLDP neighbors)", "/oid/1.3.6.1.4.1.9.9.23 (CDP)", "/oid/1.3.6.1.4.1.9.9.109 (CPU)", "/oid/1.3.6.1.4.1.9.9.48 (memory pools)"},
	}, nil
}

func (i *ios) RawChange(_ context.Context, r Raw, dry bool) (RawResult, error) {
	return RawResult{DryRun: dry}, errors.New("classic Cisco IOS is read over SNMP and cannot be changed from here")
}
