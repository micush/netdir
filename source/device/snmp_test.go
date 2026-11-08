package device

import (
	"context"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- an agent written from the RFCs, for the tests ----

func oidLess(a, b string) bool {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		m, _ := strconv.Atoi(x[i])
		n, _ := strconv.Atoi(y[i])
		if m != n {
			return m < n
		}
	}
	return len(x) < len(y)
}

func encVal(v snmpVar) []byte {
	switch v.Tag {
	case tagInt:
		return berInt(v.Int)
	case tagCounter32, tagGauge32, tagTicks, tagCounter64:
		b := []byte{0}
		for s := 56; s >= 0; s -= 8 {
			b = append(b, byte(uint64(v.Int)>>uint(s)))
		}
		for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
			b = b[1:]
		}
		return tlv(v.Tag, b)
	case tagNoObject, tagNoInst, tagEndOfMIB:
		return []byte{v.Tag, 0}
	}
	return tlv(v.Tag, v.Bytes)
}

func encResponse(tag byte, id, status int64, vars []snmpVar) []byte {
	var vb []byte
	for _, v := range vars {
		oid, _ := berOID(v.OID)
		vb = append(vb, tlv(tagSeq, oid, encVal(v))...)
	}
	return tlv(tag, berInt(id), berInt(status), berInt(0), tlv(tagSeq, vb))
}

type testAgent struct {
	mib      []snmpVar
	comm     string
	usm      *snmpUSM // the agent's own view of its user; nil for v2c only
	engineID []byte
	conn     net.PacketConn
}

func vInt(o string, n int64) snmpVar    { return snmpVar{OID: o, Tag: tagInt, Int: n} }
func vStr(o, s string) snmpVar          { return snmpVar{OID: o, Tag: tagOctets, Bytes: []byte(s)} }
func vBytes(o string, b []byte) snmpVar { return snmpVar{OID: o, Tag: tagOctets, Bytes: b} }
func vCtr(o string, n int64) snmpVar    { return snmpVar{OID: o, Tag: tagCounter64, Int: n} }
func vGauge(o string, n int64) snmpVar  { return snmpVar{OID: o, Tag: tagGauge32, Int: n} }
func vTicks(o string, n int64) snmpVar  { return snmpVar{OID: o, Tag: tagTicks, Int: n} }
func vIP(o string, ip string) snmpVar {
	return snmpVar{OID: o, Tag: tagIPAddr, Bytes: net.ParseIP(ip).To4()}
}

func (a *testAgent) answer(p snmpPDU) snmpPDU {
	out := snmpPDU{Tag: pduResponse, ReqID: p.ReqID}
	switch p.Tag {
	case pduGet:
		for _, q := range p.Vars {
			found := false
			for _, m := range a.mib {
				if m.OID == q.OID {
					out.Vars, found = append(out.Vars, m), true
				}
			}
			if !found {
				out.Vars = append(out.Vars, snmpVar{OID: q.OID, Tag: tagNoInst})
			}
		}
	case pduGetNext, pduGetBulk:
		max := 1
		if p.Tag == pduGetBulk {
			max = int(p.ErrIndex)
		}
		cur := p.Vars[0].OID
		for n := 0; n < max; n++ {
			i := sort.Search(len(a.mib), func(i int) bool { return oidLess(cur, a.mib[i].OID) })
			if i >= len(a.mib) {
				out.Vars = append(out.Vars, snmpVar{OID: cur, Tag: tagEndOfMIB})
				break
			}
			out.Vars = append(out.Vars, a.mib[i])
			cur = a.mib[i].OID
		}
	}
	return out
}

func (a *testAgent) serve(t *testing.T) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		if out := a.handle(t, raw); out != nil {
			_, _ = a.conn.WriteTo(out, from)
		}
	}
}

func (a *testAgent) handle(t *testing.T, raw []byte) []byte {
	_, c, _, err := next(raw)
	if err != nil {
		return nil
	}
	_, vb, c, _ := next(c)
	ver := parseInt(vb)
	if ver == 1 {
		_, comm, c, _ := next(c)
		if string(comm) != a.comm {
			return nil
		}
		pt, pc, _, _ := next(c)
		p, err := decodePDU(pt, pc)
		if err != nil {
			return nil
		}
		r := a.answer(p)
		return tlv(tagSeq, berInt(1), tlv(tagOctets, comm), encResponse(pduResponse, r.ReqID, 0, r.Vars))
	}
	// v3: a message with no engine ID asks for discovery and gets a report with ours
	_, hdr, c, _ := next(c)
	_, mid, _, _ := next(hdr)
	msgID := parseInt(mid)
	_, spw, _, _ := next(c)
	_, sp, _, _ := next(spw)
	_, e, _, _ := next(sp)
	if len(e) == 0 {
		rep := encResponse(pduReport, 0, 0, []snmpVar{{OID: "1.3.6.1.6.3.15.1.1.4.0", Tag: tagCounter32, Int: 1}})
		ru := &snmpUSM{engineID: a.engineID, boots: 7, etime: 100, synced: time.Now()}
		scoped := tlv(tagSeq, tlv(tagOctets, a.engineID), tlv(tagOctets, nil), rep)
		return tlv(tagSeq, berInt(3), tlv(tagSeq, berInt(msgID), berInt(65000), tlv(tagOctets, []byte{0}), berInt(3)), ru.secParams(nil, nil), scoped)
	}
	u := a.usm
	p, _, _, _, err := u.parse(raw)
	if err != nil {
		t.Logf("agent: %v", err)
		return nil
	}
	r := a.answer(p)
	resp := encResponse(pduResponse, r.ReqID, 0, r.Vars)
	return u.build(msgID, resp)
}

func startAgent(t *testing.T, a *testAgent) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP on loopback:", err)
	}
	a.conn = pc
	go a.serve(t)
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

func iosMIB() []snmpVar {
	m := []snmpVar{
		vStr("1.3.6.1.2.1.1.1.0", "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)"),
		vTicks("1.3.6.1.2.1.1.3.0", 8640000),
		vStr("1.3.6.1.2.1.1.5.0", "sw-core-1"),
		vInt(oEntClass+".1", 11), vInt(oEntClass+".1001", 3),
		vStr(oEntModel+".1001", "WS-C2960X-48FPD-L"), vStr(oEntSerial+".1001", "FOC1234X0AB"),
		vStr(oIfDescr+".1", "GigabitEthernet1/0/1"), vStr(oIfDescr+".2", "Vlan10"),
		vInt(oIfType+".1", 6), vInt(oIfType+".2", 53), vInt(oIfMTU+".1", 1500), vInt(oIfMTU+".2", 1500),
		vBytes(oIfMAC+".1", []byte{0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}), vBytes(oIfMAC+".2", []byte{0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5f}),
		vInt(oIfAdmin+".1", 1), vInt(oIfAdmin+".2", 1), vInt(oIfOper+".1", 1), vInt(oIfOper+".2", 2),
		vStr(oIfName+".1", "Gi1/0/1"), vStr(oIfName+".2", "Vl10"), vStr(oIfAlias+".1", "to core"), vStr(oIfAlias+".2", ""),
		vGauge(oIfHighSpd+".1", 1000), vGauge(oIfHighSpd+".2", 1000),
		vCtr(oIfHCInOct+".1", 5000000000), vCtr(oIfHCOutOct+".1", 42), vCtr(oIfHCInUc+".1", 10), vCtr(oIfHCInMc+".1", 5), vCtr(oIfInErr+".1", 3),
		vIP(oIPAddr+".10.1.10.2", "10.1.10.2"), vInt(oIPIfIdx+".10.1.10.2", 2), vIP(oIPMask+".10.1.10.2", "255.255.255.0"),
		vStr(oLldpLocDsc+".1", "Gi1/0/1"),
		vStr(oLldpRemSys+".0.1.1", "dist-1"), vStr(oLldpRemID+".0.1.1", "Te1/1/1"), vStr(oLldpRemSD+".0.1.1", "Cisco IOS XE"),
		vStr(oCdpDevID+".1.1", "dist-1.example.net"), vStr(oCdpPort+".1.1", "TenGigabitEthernet1/1/1"), vStr(oCdpPlat+".1.1", "cisco C9300"), vIP(oCdpAddr+".1.1", "10.1.10.1"),
		vIP(oRtDest+".0.0.0.0.0.0.0.0.0.10.1.10.1", "0.0.0.0"), vIP(oRtMask+".0.0.0.0.0.0.0.0.0.10.1.10.1", "0.0.0.0"), vIP(oRtNext+".0.0.0.0.0.0.0.0.0.10.1.10.1", "10.1.10.1"),
		vInt(oRtIf+".0.0.0.0.0.0.0.0.0.10.1.10.1", 2), vInt(oRtProto+".0.0.0.0.0.0.0.0.0.10.1.10.1", 13), vInt(oRtMetric+".0.0.0.0.0.0.0.0.0.10.1.10.1", 110),
		vStr("1.3.6.1.6.3.18.1.1.1.2.1", "secretcomm"),
	}
	sort.Slice(m, func(i, j int) bool { return oidLess(m[i].OID, m[j].OID) })
	return m
}

func TestSNMPKeyLocalizationRFC3414(t *testing.T) {
	eid, _ := hex.DecodeString("000000000000000000000002")
	md5k := localize(snmpAuths["md5"].h, passwordToKey(snmpAuths["md5"].h, "maplesyrup"), eid)
	if hex.EncodeToString(md5k) != "526f5eed9fcce26f8964c2930787d82b" {
		t.Errorf("md5 key %x", md5k)
	}
	shak := localize(snmpAuths["sha"].h, passwordToKey(snmpAuths["sha"].h, "maplesyrup"), eid)
	if hex.EncodeToString(shak) != "6695febc9288e36282235fc7151f128497b38f3f" {
		t.Errorf("sha key %x", shak)
	}
}

func TestBERRoundTrip(t *testing.T) {
	for _, n := range []int64{0, 1, 127, 128, 255, 256, 65535, -1, -128, -129, 1 << 31, -(1 << 31)} {
		_, c, _, err := next(berInt(n))
		if err != nil || parseInt(c) != n {
			t.Errorf("%d: %v %d", n, err, parseInt(c))
		}
	}
	o, err := berOID("1.3.6.1.4.1.9.9.23.1.2.1.1.6.1000")
	if err != nil {
		t.Fatal(err)
	}
	_, c, _, _ := next(o)
	if parseOID(c) != "1.3.6.1.4.1.9.9.23.1.2.1.1.6.1000" {
		t.Errorf("%s", parseOID(c))
	}
	if _, err := berOID("1.3"); err != nil {
		t.Errorf("two numbers: %v", err)
	}
	if _, err := berOID("3.1.2"); err == nil {
		t.Errorf("a first number of 3 was accepted")
	}
}

func iosDevice(addr string) Device {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return Device{Name: "sw1", Platform: "ios", Address: host, Port: p, Credential: "x"}
}

func TestIOSOverSNMPv2c(t *testing.T) {
	a := &testAgent{mib: iosMIB(), comm: "ro-comm-7q2x"}
	d := iosDevice(startAgent(t, a))
	drv, err := Open(d, Credential{Name: "x", Token: "ro-comm-7q2x"})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f, err := drv.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.Hostname != "sw-core-1" || f.OSVersion != "15.2(7)E3" || f.Model != "WS-C2960X-48FPD-L" || f.Serial != "FOC1234X0AB" || f.UptimeS != 86400 || f.Vendor != "Cisco" {
		t.Errorf("facts: %+v", f)
	}
	ifs, err := drv.Interfaces(ctx)
	if err != nil || len(ifs) != 2 {
		t.Fatalf("interfaces: %v %+v", err, ifs)
	}
	if ifs[0].Name != "Gi1/0/1" || ifs[0].Description != "to core" || ifs[0].OperUp == nil || !*ifs[0].OperUp || ifs[0].SpeedMbps != 1000 || ifs[0].MAC != "00:1a:2b:3c:4d:5e" {
		t.Errorf("interface 1: %+v", ifs[0])
	}
	if ifs[1].OperUp == nil || *ifs[1].OperUp || len(ifs[1].Addresses) != 1 || ifs[1].Addresses[0] != "10.1.10.2/24" {
		t.Errorf("interface 2: %+v", ifs[1])
	}
	ports, err := drv.(Porter).Ports(ctx)
	if err != nil || len(ports) != 2 || ports[0].Counters.InOctets != 5000000000 || ports[0].Counters.InErrors != 3 || ports[0].Counters.InPackets != 15 || ports[0].Type != "ethernet" {
		t.Errorf("ports: %v %+v", err, ports)
	}
	ns, err := drv.Neighbors(ctx)
	if err != nil || len(ns) != 2 {
		t.Fatalf("neighbors: %v %+v", err, ns)
	}
	if ns[0].Protocol != "lldp" || ns[0].LocalPort != "Gi1/0/1" || ns[0].RemoteName != "dist-1" || ns[0].RemotePort != "Te1/1/1" {
		t.Errorf("lldp: %+v", ns[0])
	}
	if ns[1].Protocol != "cdp" || ns[1].RemoteName != "dist-1.example.net" || ns[1].RemoteAddr != "10.1.10.1" || ns[1].LocalPort != "Gi1/0/1" {
		t.Errorf("cdp: %+v", ns[1])
	}
	rs, err := drv.(Router).Routes(ctx)
	if err != nil || len(rs) != 1 || rs[0].Prefix != "0.0.0.0/0" || rs[0].NextHop != "10.1.10.1" || rs[0].Protocol != "ospf" || rs[0].Interface != "Vl10" || rs[0].Metric != 110 {
		t.Errorf("routes: %v %+v", err, rs)
	}
	// a subtree by its OID, and the subtrees that hold SNMP's own communities are not read
	txt, err := drv.Show(ctx, "show oid 1.3.6.1.2.1.1")
	if err != nil || !strings.Contains(txt, "sw-core-1") {
		t.Errorf("show oid: %v %q", err, txt)
	}
	for _, o := range []string{"1.3.6.1.6.3.18.1.1", "1.3.6.1.6.3", "1.3.6.1.6", "1.3.6.1"} {
		txt, err = drv.Show(ctx, "show oid "+o)
		if strings.Contains(txt, "secretcomm") {
			t.Errorf("%s: the community was read: %q %v", o, txt, err)
		}
	}
	if _, err := drv.Show(ctx, "show running-config"); err == nil {
		t.Errorf("a CLI command was accepted")
	}
	if _, err := drv.Config(ctx); err == nil {
		t.Errorf("config answered")
	}
	if _, err := drv.(RawChanger).RawChange(ctx, Raw{Lines: []string{"x"}}, false); err == nil {
		t.Errorf("a change was accepted")
	}
	v, _, err := drv.(APIer).APIGet(ctx, "/oid/1.3.6.1.2.1.1")
	if err != nil || !strings.Contains(strings.ReplaceAll(toJSON(v), " ", ""), "sw-core-1") {
		t.Errorf("api: %v %v", err, v)
	}
	if _, _, err := drv.(APIer).APIGet(ctx, "/oid/1.3.6.1.6.3.18"); err == nil {
		t.Errorf("api read the communities")
	}
}

func TestIOSOverSNMPv2cWrongCommunity(t *testing.T) {
	a := &testAgent{mib: iosMIB(), comm: "ro-comm-7q2x"}
	d := iosDevice(startAgent(t, a))
	drv, _ := Open(d, Credential{Name: "x", Token: "nope"})
	defer drv.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	i := drv.(*ios)
	i.c.timeout, i.c.retries = 100*time.Millisecond, 0
	if _, err := drv.Facts(ctx); err == nil || strings.Contains(err.Error(), "nope") {
		t.Errorf("facts: %v", err)
	}
}

func TestIOSOverSNMPv3(t *testing.T) {
	for _, c := range []struct {
		name         string
		cred         Credential
		opts         map[string]string
		auth, priv   string
		authP, privP string
	}{
		{"authNoPriv sha", Credential{Username: "netdir", Password: "authpass1234"}, nil, "sha", "", "authpass1234", ""},
		{"authPriv sha256 aes", Credential{Username: "netdir", Password: "authpass1234", Token: "privpass1234"}, map[string]string{"auth": "sha256"}, "sha256", "aes", "authpass1234", "privpass1234"},
		{"authPriv md5 des", Credential{Username: "netdir", Password: "authpass1234", Token: "privpass1234"}, map[string]string{"auth": "md5", "priv": "des"}, "md5", "des", "authpass1234", "privpass1234"},
		{"authPriv sha512 aes", Credential{Username: "netdir", Password: "authpass1234", Token: "privpass1234"}, map[string]string{"auth": "sha512"}, "sha512", "aes", "authpass1234", "privpass1234"},
	} {
		t.Run(c.name, func(t *testing.T) {
			au := snmpAuths[c.auth]
			ag := &snmpUSM{user: "netdir", auth: &au, authPass: c.authP, priv: c.priv, privPass: c.privP}
			eid, _ := hex.DecodeString("80001f8880e9b104617a6e1f6a")
			a := &testAgent{mib: iosMIB(), usm: ag, engineID: eid}
			ag.setEngine(eid, 7, 100)
			d := iosDevice(startAgent(t, a))
			d.Options = c.opts
			drv, err := Open(d, c.cred)
			if err != nil {
				t.Fatal(err)
			}
			defer drv.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f, err := drv.Facts(ctx)
			if err != nil || f.Hostname != "sw-core-1" || f.Serial != "FOC1234X0AB" {
				t.Fatalf("facts: %v %+v", err, f)
			}
			ifs, err := drv.Interfaces(ctx)
			if err != nil || len(ifs) != 2 {
				t.Errorf("interfaces: %v %d", err, len(ifs))
			}
		})
	}
}

func TestIOSLoginRefusals(t *testing.T) {
	for _, c := range []struct {
		d Device
		c Credential
	}{
		{Device{Name: "a", Platform: "ios", Address: "x"}, Credential{}},
		{Device{Name: "a", Platform: "ios", Address: "x", Options: map[string]string{"snmp_version": "3"}}, Credential{Token: "ro-comm-7q2x"}},
		{Device{Name: "a", Platform: "ios", Address: "x"}, Credential{Username: "u", Password: "sh0rt1"}},
		{Device{Name: "a", Platform: "ios", Address: "x", Options: map[string]string{"auth": "rot13"}}, Credential{Username: "u", Password: "longenough1"}},
		{Device{Name: "a", Platform: "ios", Address: "x", Options: map[string]string{"snmp_version": "1"}}, Credential{Token: "ro-comm-7q2x"}},
	} {
		if _, err := Open(c.d, c.c); err == nil {
			t.Errorf("%+v %+v was accepted", c.d.Options, c.c.Username)
		}
	}
}
