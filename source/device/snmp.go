package device

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"strconv"
	"strings"
	"time"
)

// A small SNMP client in the standard library: BER, SNMPv2c and SNMPv3 (the user-based security model, RFC 3414, with the
// SHA-2 authentication of RFC 7860 and AES-128 privacy of RFC 3826).  It only reads: GET, GETNEXT and GETBULK.
//
// Not tried against a real device: the message layout and the keys follow the RFCs, and the tests check the key
// localization against the RFC 3414 examples and talk to an agent written from the same RFCs.

const (
	tagInt       = 0x02
	tagOctets    = 0x04
	tagNull      = 0x05
	tagOID       = 0x06
	tagSeq       = 0x30
	tagIPAddr    = 0x40
	tagCounter32 = 0x41
	tagGauge32   = 0x42
	tagTicks     = 0x43
	tagOpaque    = 0x44
	tagCounter64 = 0x46
	tagNoObject  = 0x80
	tagNoInst    = 0x81
	tagEndOfMIB  = 0x82
	pduGet       = 0xa0
	pduGetNext   = 0xa1
	pduResponse  = 0xa2
	pduGetBulk   = 0xa5
	pduReport    = 0xa8
)

// snmpVar is one variable of an answer: its OID in dotted form and its value.
type snmpVar struct {
	OID   string
	Tag   byte
	Int   int64  // INTEGER, counters, gauges, time ticks
	Bytes []byte // OCTET STRING, IpAddress, Opaque; the dotted OID of an OBJECT IDENTIFIER value is in Str
	Str   string
}

// End says that the agent has nothing here (noSuchObject, noSuchInstance, endOfMibView).
func (v snmpVar) End() bool {
	return v.Tag == tagNoObject || v.Tag == tagNoInst || v.Tag == tagEndOfMIB
}

// Text is the value as text: a string as it is (printable) or as hex, a number in decimal, an address dotted.
func (v snmpVar) Text() string {
	switch v.Tag {
	case tagOctets, tagOpaque:
		if printable(v.Bytes) {
			return string(v.Bytes)
		}
		return hexColon(v.Bytes)
	case tagIPAddr:
		if len(v.Bytes) == 4 {
			return net.IP(v.Bytes).String()
		}
	case tagOID:
		return v.Str
	case tagNull, tagNoObject, tagNoInst, tagEndOfMIB:
		return ""
	}
	return strconv.FormatInt(v.Int, 10)
}

func printable(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func hexColon(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

// ---- BER ----

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for x := n; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	out := append([]byte{tag}, berLen(n)...)
	for _, c := range content {
		out = append(out, c...)
	}
	return out
}

func berInt(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	i := 0
	for i < 7 && (b[i] == 0 && b[i+1]&0x80 == 0 || b[i] == 0xff && b[i+1]&0x80 != 0) {
		i++
	}
	return tlv(tagInt, b[i:])
}

func berOID(s string) ([]byte, error) {
	parts := strings.Split(strings.Trim(s, "."), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oid %q: needs at least two numbers", s)
	}
	n := make([]uint64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("oid %q: %q is not a number", s, p)
		}
		n[i] = v
	}
	if n[0] > 2 || n[0] < 2 && n[1] > 39 {
		return nil, fmt.Errorf("oid %q: the first two numbers are not valid", s)
	}
	out := []byte{byte(n[0]*40 + n[1])}
	for _, v := range n[2:] {
		var enc []byte
		for x := v; ; x >>= 7 {
			enc = append([]byte{byte(x & 0x7f)}, enc...)
			if x < 0x80 {
				break
			}
		}
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		out = append(out, enc...)
	}
	return tlv(tagOID, out), nil
}

func parseOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var parts []string
	parts = append(parts, strconv.Itoa(int(b[0])/40), strconv.Itoa(int(b[0])%40))
	var v uint64
	for _, c := range b[1:] {
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(v, 10))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

var errBER = errors.New("the SNMP answer is malformed")

// next reads one TLV from b: its tag, its content and what follows.
func next(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, errBER
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		i = 2 + n
	}
	if l < 0 || len(b) < i+l {
		return 0, nil, nil, errBER
	}
	return tag, b[i : i+l], b[i+l:], nil
}

func parseInt(b []byte) int64 {
	var v int64
	if len(b) > 0 && b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}

func parseUint(b []byte) int64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return int64(v)
}

func parseVar(oid string, tag byte, c []byte) snmpVar {
	v := snmpVar{OID: oid, Tag: tag}
	switch tag {
	case tagInt:
		v.Int = parseInt(c)
	case tagCounter32, tagGauge32, tagTicks, tagCounter64:
		v.Int = parseUint(c)
	case tagOID:
		v.Str = parseOID(c)
	default:
		v.Bytes = append([]byte(nil), c...)
	}
	return v
}

// ---- messages ----

type snmpPDU struct {
	Tag       byte
	ReqID     int64
	ErrStatus int64
	ErrIndex  int64
	Vars      []snmpVar
}

func encodePDU(tag byte, reqID, a, b int64, oids []string) ([]byte, error) {
	var vb []byte
	for _, o := range oids {
		oid, err := berOID(o)
		if err != nil {
			return nil, err
		}
		vb = append(vb, tlv(tagSeq, oid, []byte{tagNull, 0})...)
	}
	return tlv(tag, berInt(reqID), berInt(a), berInt(b), tlv(tagSeq, vb)), nil
}

func decodePDU(tag byte, c []byte) (snmpPDU, error) {
	p := snmpPDU{Tag: tag}
	t, v, rest, err := next(c)
	if err != nil || t != tagInt {
		return p, errBER
	}
	p.ReqID = parseInt(v)
	if t, v, rest, err = next(rest); err != nil || t != tagInt {
		return p, errBER
	}
	p.ErrStatus = parseInt(v)
	if t, v, rest, err = next(rest); err != nil || t != tagInt {
		return p, errBER
	}
	p.ErrIndex = parseInt(v)
	t, v, _, err = next(rest)
	if err != nil || t != tagSeq {
		return p, errBER
	}
	for len(v) > 0 {
		var item []byte
		if t, item, v, err = next(v); err != nil || t != tagSeq {
			return p, errBER
		}
		ot, oc, vr, err := next(item)
		if err != nil || ot != tagOID {
			return p, errBER
		}
		vt, vc, _, err := next(vr)
		if err != nil {
			return p, errBER
		}
		p.Vars = append(p.Vars, parseVar(parseOID(oc), vt, vc))
	}
	return p, nil
}

// ---- the user-based security model ----

// snmpAuth is an authentication protocol: the hash and the length of the code the message carries.
type snmpAuth struct {
	name string
	h    func() hash.Hash
	mac  int
}

var snmpAuths = map[string]snmpAuth{
	"md5":    {"md5", md5.New, 12},
	"sha":    {"sha", sha1.New, 12},
	"sha1":   {"sha", sha1.New, 12},
	"sha224": {"sha224", sha256.New224, 16},
	"sha256": {"sha256", sha256.New, 24},
	"sha384": {"sha384", sha512.New384, 32},
	"sha512": {"sha512", sha512.New, 48},
}

// passwordToKey is RFC 3414 A.2: the password repeated to one megabyte, hashed.
func passwordToKey(h func() hash.Hash, pw string) []byte {
	d := h()
	buf := make([]byte, 0, 64)
	n := 0
	for n < 1048576 {
		for i := 0; i < 64; i++ {
			buf = append(buf, pw[(n+i)%len(pw)])
		}
		d.Write(buf)
		buf = buf[:0]
		n += 64
	}
	return d.Sum(nil)
}

// localize is RFC 3414 A.2: the key of one engine.
func localize(h func() hash.Hash, ku, engineID []byte) []byte {
	d := h()
	d.Write(ku)
	d.Write(engineID)
	d.Write(ku)
	return d.Sum(nil)
}

// snmpUSM is the v3 state of a session.
type snmpUSM struct {
	user     string
	auth     *snmpAuth
	authPass string
	priv     string // "", "aes" or "des"
	privPass string

	engineID []byte
	boots    int64
	etime    int64
	synced   time.Time
	authKey  []byte
	privKey  []byte
	salt     uint64
}

func (u *snmpUSM) setEngine(id []byte, boots, t int64) {
	u.boots, u.etime, u.synced = boots, t, time.Now()
	if bytes.Equal(id, u.engineID) && (u.auth == nil || u.authKey != nil) {
		return
	}
	u.engineID = append([]byte(nil), id...)
	u.authKey, u.privKey = nil, nil
	if u.auth != nil && u.authPass != "" {
		u.authKey = localize(u.auth.h, passwordToKey(u.auth.h, u.authPass), u.engineID)
		if u.priv != "" {
			pw := u.privPass
			if pw == "" {
				pw = u.authPass
			}
			u.privKey = localize(u.auth.h, passwordToKey(u.auth.h, pw), u.engineID)
		}
	}
}

func (u *snmpUSM) now() int64 { return u.etime + int64(time.Since(u.synced).Seconds()) }

func (u *snmpUSM) flags(reportable bool) byte {
	var f byte
	if u.authKey != nil {
		f |= 1
		if u.privKey != nil {
			f |= 2
		}
	}
	if reportable {
		f |= 4
	}
	return f
}

// secParams encodes msgSecurityParameters with the code and the salt given.
func (u *snmpUSM) secParams(mac, salt []byte) []byte {
	return tlv(tagOctets, tlv(tagSeq, tlv(tagOctets, u.engineID), berInt(u.boots), berInt(u.now()), tlv(tagOctets, []byte(u.user)),
		tlv(tagOctets, mac), tlv(tagOctets, salt)))
}

func (u *snmpUSM) encrypt(plain []byte) (cipherText, salt []byte, err error) {
	u.salt++
	switch u.priv {
	case "aes":
		salt = make([]byte, 8)
		binary.BigEndian.PutUint64(salt, u.salt^randUint64())
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv, uint32(u.boots))
		binary.BigEndian.PutUint32(iv[4:], uint32(u.now()))
		copy(iv[8:], salt)
		blk, err := aes.NewCipher(u.privKey[:16])
		if err != nil {
			return nil, nil, err
		}
		out := make([]byte, len(plain))
		cipher.NewCFBEncrypter(blk, iv).XORKeyStream(out, plain)
		return out, salt, nil
	case "des":
		salt = make([]byte, 8)
		binary.BigEndian.PutUint32(salt, uint32(u.boots))
		binary.BigEndian.PutUint32(salt[4:], uint32(u.salt))
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = u.privKey[8+i] ^ salt[i]
		}
		blk, err := des.NewCipher(u.privKey[:8])
		if err != nil {
			return nil, nil, err
		}
		pad := append([]byte(nil), plain...)
		for len(pad)%8 != 0 {
			pad = append(pad, 0)
		}
		out := make([]byte, len(pad))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, pad)
		return out, salt, nil
	}
	return nil, nil, errors.New("no privacy protocol")
}

func (u *snmpUSM) decrypt(ct, salt []byte, boots, etime int64) ([]byte, error) {
	switch u.priv {
	case "aes":
		if len(salt) != 8 {
			return nil, errBER
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv, uint32(boots))
		binary.BigEndian.PutUint32(iv[4:], uint32(etime))
		copy(iv[8:], salt)
		blk, err := aes.NewCipher(u.privKey[:16])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(ct))
		cipher.NewCFBDecrypter(blk, iv).XORKeyStream(out, ct)
		return out, nil
	case "des":
		if len(salt) != 8 || len(ct)%8 != 0 {
			return nil, errBER
		}
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = u.privKey[8+i] ^ salt[i]
		}
		blk, err := des.NewCipher(u.privKey[:8])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(ct))
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
		return out, nil
	}
	return nil, errors.New("no privacy protocol")
}

func randUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// ---- the session ----

// snmpConn is a UDP conversation with one agent.
type snmpConn struct {
	addr    string
	version int // 1 (v2c) or 3
	comm    string
	usm     *snmpUSM

	conn    net.Conn
	reqID   int64
	timeout time.Duration
	retries int
}

func newSNMPConn(addr string) *snmpConn {
	return &snmpConn{addr: addr, reqID: int64(randUint64() & 0x3fffffff), timeout: 3 * time.Second, retries: 2}
}

func (s *snmpConn) close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *snmpConn) exchange(ctx context.Context, msg []byte) ([]byte, error) {
	if s.conn == nil {
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", s.addr)
		if err != nil {
			return nil, err
		}
		s.conn = c
	}
	var last error
	for try := 0; try <= s.retries; try++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dl := time.Now().Add(s.timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(dl) {
			dl = d
		}
		_ = s.conn.SetDeadline(dl)
		if _, err := s.conn.Write(msg); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := s.conn.Read(buf)
		if err == nil {
			return buf[:n], nil
		}
		last = err
	}
	return nil, fmt.Errorf("the device did not answer over SNMP (%v): is SNMP on, the community or user right, and UDP %s open?", last, s.addr)
}

// request sends one PDU and returns the answer's PDU.
func (s *snmpConn) request(ctx context.Context, tag byte, a, b int64, oids []string) (snmpPDU, error) {
	s.reqID++
	pdu, err := encodePDU(tag, s.reqID, a, b, oids)
	if err != nil {
		return snmpPDU{}, err
	}
	if s.version != 3 {
		msg := tlv(tagSeq, berInt(1), tlv(tagOctets, []byte(s.comm)), pdu)
		raw, err := s.exchange(ctx, msg)
		if err != nil {
			return snmpPDU{}, err
		}
		return decodeV2(raw)
	}
	return s.requestV3(ctx, pdu, s.reqID)
}

func decodeV2(raw []byte) (snmpPDU, error) {
	t, c, _, err := next(raw)
	if err != nil || t != tagSeq {
		return snmpPDU{}, errBER
	}
	if t, _, c, err = next(c); err != nil || t != tagInt { // version
		return snmpPDU{}, errBER
	}
	if t, _, c, err = next(c); err != nil || t != tagOctets { // community
		return snmpPDU{}, errBER
	}
	t, pc, _, err := next(c)
	if err != nil {
		return snmpPDU{}, errBER
	}
	return decodePDU(t, pc)
}

func (s *snmpConn) requestV3(ctx context.Context, pdu []byte, reqID int64) (snmpPDU, error) {
	u := s.usm
	if u.engineID == nil { // discovery: an empty request the agent answers with its engine ID
		if err := s.discover(ctx); err != nil {
			return snmpPDU{}, err
		}
	}
	for attempt := 0; ; attempt++ {
		raw, err := s.exchange(ctx, u.build(reqID, pdu))
		if err != nil {
			return snmpPDU{}, err
		}
		p, boots, etime, eid, err := u.parse(raw)
		if err != nil {
			return snmpPDU{}, err
		}
		if p.Tag == pduReport {
			if attempt == 0 && len(p.Vars) > 0 {
				switch p.Vars[0].OID {
				case "1.3.6.1.6.3.15.1.1.2.0", "1.3.6.1.6.3.15.1.1.4.0": // not in time window, unknown engine ID
					u.setEngine(eid, boots, etime)
					continue
				case "1.3.6.1.6.3.15.1.1.3.0":
					return p, errors.New("the device does not know the SNMP user " + strconv.Quote(u.user))
				case "1.3.6.1.6.3.15.1.1.5.0":
					return p, errors.New("the device refused the SNMP authentication: wrong password or authentication protocol")
				case "1.3.6.1.6.3.15.1.1.1.0":
					return p, errors.New("the device does not offer the SNMP security level asked for (authentication or privacy)")
				case "1.3.6.1.6.3.15.1.1.6.0":
					return p, errors.New("the device could not decrypt the SNMP request: wrong privacy password or protocol")
				}
			}
			return p, errors.New("the device answered an SNMPv3 report")
		}
		u.setEngine(eid, boots, etime)
		return p, nil
	}
}

func (s *snmpConn) discover(ctx context.Context) error {
	u := s.usm
	saved := u.user
	savedAuth, savedPriv := u.authKey, u.privKey
	u.user, u.authKey, u.privKey, u.engineID = "", nil, nil, nil
	pdu, _ := encodePDU(pduGet, 0, 0, 0, nil)
	raw, err := s.exchange(ctx, u.build(0, pdu))
	u.user, u.authKey, u.privKey = saved, savedAuth, savedPriv
	if err != nil {
		return err
	}
	_, boots, etime, eid, err := u.parse(raw)
	if err != nil {
		return err
	}
	if len(eid) == 0 {
		return errors.New("the device gave no SNMP engine ID")
	}
	u.setEngine(eid, boots, etime)
	return nil
}

// build makes a v3 message with the PDU, signed and encrypted as the user's level says.
func (u *snmpUSM) build(msgID int64, pdu []byte) []byte {
	scoped := tlv(tagSeq, tlv(tagOctets, u.engineID), tlv(tagOctets, nil), pdu)
	header := tlv(tagSeq, berInt(msgID&0x7fffffff), berInt(65000), tlv(tagOctets, []byte{u.flags(true)}), berInt(3))
	var data, salt []byte
	if u.privKey != nil {
		ct, sl, err := u.encrypt(scoped)
		if err != nil {
			return nil
		}
		data, salt = tlv(tagOctets, ct), sl
	} else {
		data = scoped
	}
	if u.authKey == nil {
		return tlv(tagSeq, berInt(3), header, u.secParams(nil, salt), data)
	}
	n := u.auth.mac
	zero := u.secParams(make([]byte, n), salt)
	msg := tlv(tagSeq, berInt(3), header, zero, data)
	m := hmac.New(u.auth.h, u.authKey)
	m.Write(msg)
	mac := m.Sum(nil)[:n]
	real := u.secParams(mac, salt)
	i := bytes.Index(msg, zero)
	copy(msg[i:], real)
	return msg
}

// parse reads a v3 answer: its PDU, and the engine's boots, time and ID from its security parameters.
func (u *snmpUSM) parse(raw []byte) (p snmpPDU, boots, etime int64, eid []byte, err error) {
	t, c, _, err := next(raw)
	if err != nil || t != tagSeq {
		return p, 0, 0, nil, errBER
	}
	if t, _, c, err = next(c); err != nil || t != tagInt {
		return p, 0, 0, nil, errBER
	}
	t, hdr, c, err := next(c)
	if err != nil || t != tagSeq {
		return p, 0, 0, nil, errBER
	}
	var flagsB []byte
	_, _, h, _ := next(hdr) // msgID
	_, _, h, _ = next(h)    // max size
	if t, flagsB, _, err = next(h); err != nil || t != tagOctets || len(flagsB) != 1 {
		return p, 0, 0, nil, errBER
	}
	flags := flagsB[0]
	rawSec := c
	t, spw, c, err := next(c)
	if err != nil || t != tagOctets {
		return p, 0, 0, nil, errBER
	}
	_, sp, _, err := next(spw)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, eidB, sp, err := next(sp)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, bv, sp, err := next(sp)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, tv, sp, err := next(sp)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, _, sp, err = next(sp) // user
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, macB, sp, err := next(sp)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	_, saltB, _, err := next(sp)
	if err != nil {
		return p, 0, 0, nil, errBER
	}
	boots, etime, eid = parseInt(bv), parseInt(tv), append([]byte(nil), eidB...)
	if flags&1 != 0 && u.authKey != nil && len(macB) == u.auth.mac { // the code of an authenticated answer
		cp := append([]byte(nil), raw...)
		at := bytes.Index(cp, rawSec[:len(rawSec)-len(c)])
		if at >= 0 {
			if j := bytes.Index(cp[at:], macB); j >= 0 {
				for k := 0; k < len(macB); k++ {
					cp[at+j+k] = 0
				}
			}
		}
		m := hmac.New(u.auth.h, u.authKey)
		m.Write(cp)
		if !hmac.Equal(m.Sum(nil)[:u.auth.mac], macB) {
			return p, boots, etime, eid, errors.New("the SNMP answer failed its authentication check")
		}
	}
	t, d, _, err := next(c)
	if err != nil {
		return p, boots, etime, eid, errBER
	}
	if t == tagOctets { // encrypted
		if u.privKey == nil {
			return p, boots, etime, eid, errors.New("the SNMP answer is encrypted and no privacy password is set")
		}
		if d, err = u.decrypt(d, saltB, boots, etime); err != nil {
			return p, boots, etime, eid, err
		}
		if t, d, _, err = next(d); err != nil {
			return p, boots, etime, eid, errBER
		}
	}
	if t != tagSeq {
		return p, boots, etime, eid, errBER
	}
	_, _, d, err = next(d) // context engine ID
	if err != nil {
		return p, boots, etime, eid, errBER
	}
	_, _, d, err = next(d) // context name
	if err != nil {
		return p, boots, etime, eid, errBER
	}
	pt, pc, _, err := next(d)
	if err != nil {
		return p, boots, etime, eid, errBER
	}
	p, err = decodePDU(pt, pc)
	return p, boots, etime, eid, err
}

// ---- reading ----

// get reads the variables named.
func (s *snmpConn) get(ctx context.Context, oids ...string) ([]snmpVar, error) {
	p, err := s.request(ctx, pduGet, 0, 0, oids)
	if err != nil {
		return nil, err
	}
	if p.ErrStatus != 0 {
		return nil, fmt.Errorf("the device answered SNMP error %d for variable %d", p.ErrStatus, p.ErrIndex)
	}
	return p.Vars, nil
}

const snmpMaxRows = 20000

// walk reads every variable below root (GETBULK, 25 at a time), at most max.
func (s *snmpConn) walk(ctx context.Context, root string, max int) ([]snmpVar, error) {
	root = strings.Trim(root, ".")
	if max <= 0 || max > snmpMaxRows {
		max = snmpMaxRows
	}
	var out []snmpVar
	cur := root
	for len(out) < max {
		p, err := s.request(ctx, pduGetBulk, 0, 25, []string{cur})
		if err != nil {
			return out, err
		}
		if p.ErrStatus == 2 { // noSuchName: a v1 style end
			return out, nil
		}
		if p.ErrStatus != 0 {
			return out, fmt.Errorf("the device answered SNMP error %d", p.ErrStatus)
		}
		if len(p.Vars) == 0 {
			return out, nil
		}
		for _, v := range p.Vars {
			if v.End() || !strings.HasPrefix(v.OID+".", root+".") {
				return out, nil
			}
			out = append(out, v)
			cur = v.OID
			if len(out) >= max {
				break
			}
		}
	}
	return out, nil
}

// column reads one column of a table and returns the value of each row by the part of the OID after the column.
func (s *snmpConn) column(ctx context.Context, col string) (map[string]snmpVar, error) {
	vs, err := s.walk(ctx, col, 0)
	m := make(map[string]snmpVar, len(vs))
	for _, v := range vs {
		m[strings.TrimPrefix(v.OID, col+".")] = v
	}
	return m, err
}
