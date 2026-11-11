package device

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ad is Microsoft Active Directory, read over LDAP (RFC 4511), in the standard library: a simple bind over LDAPS (port 636) or over
// StartTLS (option starttls=true, port 389; the password never crosses the wire in the clear: there is no plain LDAP), then searches.
//
// The device is the directory: Facts are the domain controller's root DSE; Show takes
//
//	show user NAME      up to 10 users in detail     show users NAME      up to 50, one line each
//	show computer NAME  up to 10 computers           show computers NAME
//	show group NAME     a group and its members      show domain          the domain and the controller
//
// NAME is a sign-in name (jsmith, CORP\jsmith, jsmith@corp.example.com), a mail address, a display name or the start of one; a computer
// by its name or DNS name.  A filter is built from the name as a structure (BER), never as text, so a name cannot add to it.  Only a
// fixed list of attributes is asked for: passwords, password hashes, LAPS and BitLocker secrets and security descriptors are never
// among them.  Nothing is changed: the driver has no write.
//
// Not tried against a real domain controller: the protocol follows RFC 4511 and the attribute names are Active Directory's schema; the
// tests talk to a directory written from the same documents.
type ad struct {
	d       Device
	c       Credential
	conn    net.Conn
	rd      *bufio.Reader
	msg     int64
	base    string
	rootDSE *adEntry
}

func init() { Register("ad", newAD) }

func newAD(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: Active Directory needs a login with a user name (user@domain, DOMAIN\\user or a DN) and a password; an anonymous bind is not used", d.Name)
	}
	if b := strings.TrimSpace(d.Options["base"]); b != "" && !strings.Contains(b, "=") {
		return nil, fmt.Errorf("device %s: option base is a distinguished name such as DC=corp,DC=example,DC=com", d.Name)
	}
	return &ad{d: d, c: c, base: strings.TrimSpace(d.Options["base"])}, nil
}

const (
	adMaxMsg     = 8 << 20
	adListMax    = 50
	adDetailMax  = 10
	adMemberShow = 30
)

// ---- the connection ----

func (a *ad) tlsConfig() (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: a.d.Address}
	switch {
	case a.d.Insecure:
		tc.InsecureSkipVerify = true
	case a.d.CAPEM != "":
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(a.d.CAPEM)) {
			return nil, fmt.Errorf("device %s: ca_pem holds no PEM certificate", a.d.Name)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

func (a *ad) startTLS() bool { return strings.EqualFold(a.d.Options["starttls"], "true") }

// connect opens the connection and binds, once per driver.
func (a *ad) connect(ctx context.Context) error {
	if a.conn != nil {
		return nil
	}
	tc, err := a.tlsConfig()
	if err != nil {
		return err
	}
	port := a.d.Port
	if port == 0 {
		port = 636
		if a.startTLS() {
			port = 389
		}
	}
	dl := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dl.DialContext(ctx, "tcp", net.JoinHostPort(a.d.Address, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()
	if dlt, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dlt)
	} else {
		_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	}
	a.conn = raw
	a.rd = bufio.NewReader(raw)
	if a.startTLS() {
		if err := a.doStartTLS(); err != nil {
			a.drop()
			return err
		}
		t := tls.Client(raw, tc)
		if err := t.HandshakeContext(ctx); err != nil {
			a.drop()
			return fmt.Errorf("TLS: %w", err)
		}
		a.conn, a.rd = t, bufio.NewReader(t)
	} else {
		t := tls.Client(raw, tc)
		if err := t.HandshakeContext(ctx); err != nil {
			a.drop()
			return fmt.Errorf("TLS: %w (LDAPS is port 636; for StartTLS on 389 set the option starttls=true)", err)
		}
		a.conn, a.rd = t, bufio.NewReader(t)
	}
	if err := a.bind(); err != nil {
		a.drop()
		return err
	}
	return nil
}

func (a *ad) drop() {
	if a.conn != nil {
		_ = a.conn.Close()
	}
	a.conn, a.rd = nil, nil
}

func (a *ad) Close(context.Context) {
	if a.conn == nil {
		return
	}
	a.msg++
	_ = a.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = a.conn.Write(tlv(tagSeq, berInt(a.msg), []byte{0x42, 0x00})) // unbindRequest
	a.drop()
}

// deadline puts the context's end (or 30 s) on the connection for the next exchange.
func (a *ad) deadline(ctx context.Context) func() {
	dl := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = a.conn.SetDeadline(dl)
	conn := a.conn
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	return func() { stop() }
}

func (a *ad) send(op []byte) (int64, error) {
	a.msg++
	if _, err := a.conn.Write(tlv(tagSeq, berInt(a.msg), op)); err != nil {
		return 0, err
	}
	return a.msg, nil
}

// readBER reads one TLV element from r.
func readBER(r *bufio.Reader) (tag byte, content []byte, err error) {
	if tag, err = r.ReadByte(); err != nil {
		return
	}
	l0, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n := int(l0)
	if l0&0x80 != 0 {
		k := int(l0 & 0x7f)
		if k == 0 || k > 4 {
			return 0, nil, errBER
		}
		n = 0
		for i := 0; i < k; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return 0, nil, err
			}
			n = n<<8 | int(b)
		}
	}
	if n < 0 || n > adMaxMsg {
		return 0, nil, errors.New("the directory sent a message that is too long")
	}
	content = make([]byte, n)
	if _, err = io.ReadFull(r, content); err != nil {
		return 0, nil, err
	}
	return tag, content, nil
}

// ldapMsg is one LDAPMessage: its ID, the tag of its operation and the operation's content.
func (a *ad) read() (id int64, op byte, content []byte, err error) {
	tag, c, err := readBER(a.rd)
	if err != nil {
		return 0, 0, nil, err
	}
	if tag != tagSeq {
		return 0, 0, nil, errBER
	}
	t, idb, rest, err := next(c)
	if err != nil || t != tagInt {
		return 0, 0, nil, errBER
	}
	op, content, _, err = next(rest)
	if err != nil {
		return 0, 0, nil, errBER
	}
	return parseInt(idb), op, content, nil
}

// result parses an LDAPResult: the code and the diagnostic text.
func ldapResult(c []byte) (code int, diag string, err error) {
	t, cb, rest, err := next(c)
	if err != nil || t != 0x0a {
		return 0, "", errBER
	}
	_, _, rest, err = next(rest) // matchedDN
	if err != nil {
		return 0, "", errBER
	}
	_, d, _, err := next(rest)
	if err != nil {
		return 0, "", errBER
	}
	return int(parseInt(cb)), string(d), nil
}

func (a *ad) doStartTLS() error {
	id, err := a.send(tlv(0x77, tlv(0x80, []byte("1.3.6.1.4.1.1466.20037"))))
	if err != nil {
		return err
	}
	for {
		mid, op, c, err := a.read()
		if err != nil {
			return err
		}
		if mid != id {
			continue
		}
		if op != 0x78 {
			return errors.New("the directory answered StartTLS with something else")
		}
		code, diag, err := ldapResult(c)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("the directory refused StartTLS (%d %s)", code, diag)
		}
		return nil
	}
}

func (a *ad) bind() error {
	id, err := a.send(tlv(0x60, berInt(3), tlv(tagOctets, []byte(a.c.Username)), tlv(0x80, []byte(a.c.Password))))
	if err != nil {
		return err
	}
	for {
		mid, op, c, err := a.read()
		if err != nil {
			return err
		}
		if mid != id || op != 0x61 {
			continue
		}
		code, diag, err := ldapResult(c)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 49:
			return errors.New("the directory refused the login (wrong user name or password, or the account is locked or disabled)")
		default:
			return fmt.Errorf("the directory refused the bind: %s", scrub(adDiag(code, diag), a.c))
		}
	}
}

func adDiag(code int, d string) string {
	d = strings.TrimSpace(d)
	if len(d) > 200 {
		d = d[:200] + "…"
	}
	return fmt.Sprintf("result %d %s", code, d)
}

// ---- searching ----

// adEntry is one entry of a search: its DN and its attributes (names in lower case).
type adEntry struct {
	DN    string
	Attrs map[string][]string
}

func (e adEntry) first(k string) string {
	if v := e.Attrs[strings.ToLower(k)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// filters, as BER: a name is a value of the structure and never part of text
func fEq(attr, val string) []byte {
	return tlv(0xa3, tlv(tagOctets, []byte(attr)), tlv(tagOctets, []byte(val)))
}
func fPre(attr, val string) []byte {
	return tlv(0xa4, tlv(tagOctets, []byte(attr)), tlv(tagSeq, tlv(0x80, []byte(val))))
}
func fPres(attr string) []byte { return tlv(0x87, []byte(attr)) }
func fAnd(f ...[]byte) []byte  { return tlv(0xa0, f...) }
func fOr(f ...[]byte) []byte   { return tlv(0xa1, f...) }

// search runs one search below base.  A result cut at limit is reported as cut, not as an error.
func (a *ad) search(ctx context.Context, base string, scope int, filter []byte, attrs []string, limit int) (out []adEntry, cut bool, err error) {
	if err = a.connect(ctx); err != nil {
		return nil, false, err
	}
	stop := a.deadline(ctx)
	defer stop()
	var al [][]byte
	for _, x := range attrs {
		al = append(al, tlv(tagOctets, []byte(x)))
	}
	req := tlv(0x63, tlv(tagOctets, []byte(base)), []byte{0x0a, 0x01, byte(scope)}, []byte{0x0a, 0x01, 0x00}, berInt(int64(limit)), berInt(20), []byte{0x01, 0x01, 0x00}, filter, tlv(tagSeq, al...))
	id, err := a.send(req)
	if err != nil {
		a.drop()
		return nil, false, err
	}
	for {
		mid, op, c, err := a.read()
		if err != nil {
			a.drop()
			return nil, false, err
		}
		if mid != id {
			continue
		}
		switch op {
		case 0x64: // searchResEntry
			e, err := parseAdEntry(c)
			if err != nil {
				a.drop()
				return nil, false, err
			}
			out = append(out, e)
		case 0x65: // searchResDone
			code, diag, err := ldapResult(c)
			if err != nil {
				a.drop()
				return nil, false, err
			}
			switch code {
			case 0, 10, 32: // done, a referral to another domain (not followed), no such object
				return out, false, nil
			case 4, 11: // size or time limit exceeded: what came is returned
				return out, true, nil
			case 50:
				return nil, false, errors.New("the login may not read that part of the directory (insufficient access)")
			default:
				return nil, false, fmt.Errorf("the directory refused the search: %s", scrub(adDiag(code, diag), a.c))
			}
		}
	}
}

func parseAdEntry(c []byte) (adEntry, error) {
	t, dn, rest, err := next(c)
	if err != nil || t != tagOctets {
		return adEntry{}, errBER
	}
	e := adEntry{DN: string(dn), Attrs: map[string][]string{}}
	t, attrs, _, err := next(rest)
	if err != nil || t != tagSeq {
		return adEntry{}, errBER
	}
	for len(attrs) > 0 {
		var pa []byte
		if t, pa, attrs, err = next(attrs); err != nil || t != tagSeq {
			return adEntry{}, errBER
		}
		t, name, vs, err := next(pa)
		if err != nil || t != tagOctets {
			return adEntry{}, errBER
		}
		t, set, _, err := next(vs)
		if err != nil || t != 0x31 {
			return adEntry{}, errBER
		}
		k := strings.ToLower(string(name))
		for len(set) > 0 {
			var v []byte
			if _, v, set, err = next(set); err != nil {
				return adEntry{}, errBER
			}
			e.Attrs[k] = append(e.Attrs[k], string(v))
		}
	}
	return e, nil
}

// base is the search base: the option, or the domain the controller serves.
func (a *ad) searchBase(ctx context.Context) (string, error) {
	if a.base != "" {
		return a.base, nil
	}
	r, err := a.root(ctx)
	if err != nil {
		return "", err
	}
	if b := r.first("defaultNamingContext"); b != "" {
		a.base = b
		return b, nil
	}
	return "", errors.New("the directory names no default naming context: set the option base (DC=corp,DC=example,DC=com)")
}

func (a *ad) root(ctx context.Context) (*adEntry, error) {
	if a.rootDSE != nil {
		return a.rootDSE, nil
	}
	es, _, err := a.search(ctx, "", 0, fPres("objectClass"), []string{"defaultNamingContext", "dnsHostName", "serverName", "domainFunctionality", "forestFunctionality",
		"domainControllerFunctionality", "currentTime", "ldapServiceName", "rootDomainNamingContext", "supportedLDAPVersion"}, 1)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, errors.New("the directory answered no root DSE")
	}
	a.rootDSE = &es[0]
	return a.rootDSE, nil
}

var adLevels = map[string]string{"0": "Windows 2000", "1": "Windows Server 2003 interim", "2": "Windows Server 2003", "3": "Windows Server 2008", "4": "Windows Server 2008 R2",
	"5": "Windows Server 2012", "6": "Windows Server 2012 R2", "7": "Windows Server 2016 or later"}

func (a *ad) Facts(ctx context.Context) (Facts, error) {
	r, err := a.root(ctx)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Hostname: r.first("dnsHostName"), Vendor: "Microsoft", Model: "Active Directory"}
	if l := r.first("domainFunctionality"); l != "" {
		if n, ok := adLevels[l]; ok {
			f.OSVersion = "domain level " + n
		} else {
			f.OSVersion = "domain level " + l
		}
	}
	return f, nil
}

func (a *ad) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (a *ad) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (a *ad) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// RawChange: the directory is only read.
func (a *ad) RawChange(context.Context, Raw, bool) (RawResult, error) {
	return RawResult{}, errors.New("Active Directory is only read here: users, computers and groups are not changed")
}

// ---- what is asked for ----

var (
	adUserAttrs = []string{"cn", "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "department", "title", "company", "telephoneNumber", "mobile",
		"physicalDeliveryOfficeName", "manager", "description", "distinguishedName", "userAccountControl", "lockoutTime", "pwdLastSet", "lastLogonTimestamp", "badPwdCount",
		"badPasswordTime", "whenCreated", "whenChanged", "accountExpires", "memberOf", "employeeID"}
	adCompAttrs = []string{"cn", "name", "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "lastLogonTimestamp",
		"pwdLastSet", "whenCreated", "whenChanged", "userAccountControl", "distinguishedName", "description", "location", "managedBy", "memberOf"}
	adGroupAttrs = []string{"cn", "sAMAccountName", "description", "groupType", "member", "memberOf", "managedBy", "whenCreated", "whenChanged", "distinguishedName", "mail"}
)

// adNameOK: what a name may hold; no wildcard, no parenthesis that matters (a filter is not text here, but a name is still kept plain).
func adNameOK(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" @._'#+\\$-,()&", r)) {
			return false
		}
	}
	return true
}

func adUserFilter(n string) []byte {
	if i := strings.LastIndexByte(n, '\\'); i >= 0 { // CORP\jsmith
		n = n[i+1:]
	}
	f := []([]byte){fEq("sAMAccountName", n), fEq("userPrincipalName", n), fEq("mail", n), fEq("cn", n), fEq("displayName", n)}
	if !strings.Contains(n, "@") {
		f = append(f, fPre("sAMAccountName", n), fPre("displayName", n), fPre("userPrincipalName", n), fPre("cn", n))
	}
	return fAnd(fEq("objectCategory", "person"), fEq("objectClass", "user"), fOr(f...))
}

func adCompFilter(n string) []byte {
	if i := strings.LastIndexByte(n, '\\'); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, "$")
	short := n
	if i := strings.IndexByte(n, '.'); i > 0 {
		short = n[:i]
	}
	return fAnd(fEq("objectClass", "computer"), fOr(fEq("name", short), fEq("sAMAccountName", short+"$"), fEq("dNSHostName", n), fPre("name", n), fPre("dNSHostName", n)))
}

func adGroupFilter(n string) []byte {
	return fAnd(fEq("objectClass", "group"), fOr(fEq("cn", n), fEq("sAMAccountName", n), fPre("cn", n)))
}

// ---- turning an entry into lines ----

func adFiletime(s string) string {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v >= 0x7FFFFFFFFFFFFFFF {
		return ""
	}
	t := time.Unix(v/10000000-11644473600, 0).UTC()
	if t.Year() < 1970 || t.Year() > 9000 {
		return ""
	}
	return t.Format("2006-01-02 15:04 UTC")
}

func adGenTime(s string) string {
	if t, err := time.Parse("20060102150405.0Z", s); err == nil {
		return t.Format("2006-01-02 15:04 UTC")
	}
	return s
}

// adCN is the first name of a DN: "CN=Domain Admins,CN=Users,DC=..." is "Domain Admins".
func adCN(dn string) string {
	if !strings.HasPrefix(strings.ToUpper(dn), "CN=") {
		return dn
	}
	s := dn[3:]
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == ',' {
			break
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type adLine struct{ k, v string }

func (e adEntry) groups() string {
	var g []string
	for _, d := range e.Attrs["memberof"] {
		g = append(g, adCN(d))
	}
	sort.Strings(g)
	if len(g) > adMemberShow {
		return strings.Join(g[:adMemberShow], ", ") + fmt.Sprintf(", … (%d groups)", len(g))
	}
	return strings.Join(g, ", ")
}

func (e adEntry) uac() int64 {
	n, _ := strconv.ParseInt(e.first("userAccountControl"), 10, 64)
	return n
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func userLines(e adEntry) []adLine {
	u := e.uac()
	var l []adLine
	add := func(k, v string) {
		if v != "" {
			l = append(l, adLine{k, v})
		}
	}
	add("Name", firstNon(e.first("displayName"), e.first("cn")))
	add("Account", e.first("sAMAccountName"))
	add("Sign-in name", e.first("userPrincipalName"))
	add("Mail", e.first("mail"))
	add("Enabled", yesNo(u&2 == 0))
	if lt := e.first("lockoutTime"); lt != "" && lt != "0" {
		add("Locked out", "since "+firstNon(adFiletime(lt), "unknown"))
	}
	add("Title", e.first("title"))
	add("Department", e.first("department"))
	add("Company", e.first("company"))
	add("Office", e.first("physicalDeliveryOfficeName"))
	add("Phone", firstNon(e.first("telephoneNumber"), e.first("mobile")))
	add("Manager", adCN(e.first("manager")))
	add("Employee ID", e.first("employeeID"))
	add("Sign-in changed", firstNon(adFiletime(e.first("pwdLastSet")), map[bool]string{true: "must change at next sign-in", false: ""}[e.first("pwdLastSet") == "0"]))
	if u&0x10000 != 0 {
		add("Sign-in expires", "never")
	}
	if u&0x800000 != 0 {
		add("Sign-in", "expired")
	}
	add("Last sign-in", adFiletime(e.first("lastLogonTimestamp")))
	if n := e.first("badPwdCount"); n != "" && n != "0" {
		add("Bad sign-ins", n+" (last "+firstNon(adFiletime(e.first("badPasswordTime")), "unknown")+")")
	}
	if ex := adFiletime(e.first("accountExpires")); ex != "" {
		add("Account expires", ex)
	}
	add("Created", adGenTime(e.first("whenCreated")))
	add("Changed", adGenTime(e.first("whenChanged")))
	add("Groups", e.groups())
	add("Description", e.first("description"))
	add("DN", e.DN)
	return l
}

func compLines(e adEntry) []adLine {
	var l []adLine
	add := func(k, v string) {
		if v != "" {
			l = append(l, adLine{k, v})
		}
	}
	add("Name", firstNon(e.first("name"), e.first("cn")))
	add("DNS name", e.first("dNSHostName"))
	add("Enabled", yesNo(e.uac()&2 == 0))
	add("System", strings.TrimSpace(e.first("operatingSystem")+" "+e.first("operatingSystemVersion")+" "+e.first("operatingSystemServicePack")))
	add("Last sign-in", adFiletime(e.first("lastLogonTimestamp")))
	add("Sign-in changed", adFiletime(e.first("pwdLastSet")))
	add("Location", e.first("location"))
	add("Managed by", adCN(e.first("managedBy")))
	add("Created", adGenTime(e.first("whenCreated")))
	add("Changed", adGenTime(e.first("whenChanged")))
	add("Groups", e.groups())
	add("Description", e.first("description"))
	add("DN", e.DN)
	return l
}

func groupLines(e adEntry) []adLine {
	var l []adLine
	add := func(k, v string) {
		if v != "" {
			l = append(l, adLine{k, v})
		}
	}
	add("Name", e.first("cn"))
	add("Account", e.first("sAMAccountName"))
	add("Description", e.first("description"))
	add("Mail", e.first("mail"))
	add("Managed by", adCN(e.first("managedBy")))
	n, more := 0, ""
	var mem []string
	for k, v := range e.Attrs {
		if k == "member" || strings.HasPrefix(k, "member;range=") {
			n += len(v)
			if strings.HasPrefix(k, "member;range=") {
				more = "+"
			}
			for _, d := range v {
				mem = append(mem, adCN(d))
			}
		}
	}
	sort.Strings(mem)
	add("Members", strconv.Itoa(n)+more)
	if len(mem) > adMemberShow {
		mem = append(mem[:adMemberShow], "…")
	}
	add("Member list", strings.Join(mem, ", "))
	add("Member of", e.groups())
	add("Created", adGenTime(e.first("whenCreated")))
	add("DN", e.DN)
	return l
}

// record is an entry as a map for another part of the program (the troubleshooting): the lines as keys, enabled as a bool.
func adRecord(lines []adLine, e adEntry) map[string]any {
	m := map[string]any{}
	for _, l := range lines {
		if l.v == "" {
			continue
		}
		k := strings.NewReplacer(" ", "_", "-", "_").Replace(strings.ToLower(l.k))
		m[k] = l.v
	}
	m["enabled"] = e.uac()&2 == 0
	return m
}

func (a *ad) records(ctx context.Context, filter []byte, attrs []string, lines func(adEntry) []adLine, name string, max int) ([]map[string]any, error) {
	base, err := a.searchBase(ctx)
	if err != nil {
		return nil, err
	}
	es, _, err := a.search(ctx, base, 2, filter, attrs, max*3)
	if err != nil {
		return nil, err
	}
	adSort(es, name)
	if len(es) > max {
		es = es[:max]
	}
	out := make([]map[string]any, 0, len(es))
	for _, e := range es {
		out = append(out, adRecord(lines(e), e))
	}
	return out, nil
}

// DirUsers and DirComputers are DirectoryLooker: the users (or computers) a name matches, at most 3, as records.
func (a *ad) DirUsers(ctx context.Context, who string) ([]map[string]any, error) {
	if !adNameOK(who) {
		return nil, errors.New("user: a sign-in name, mail address or display name")
	}
	return a.records(ctx, adUserFilter(who), adUserAttrs, userLines, who, 3)
}

func (a *ad) DirComputers(ctx context.Context, name string) ([]map[string]any, error) {
	if !adNameOK(name) {
		return nil, errors.New("host: a computer name")
	}
	return a.records(ctx, adCompFilter(name), adCompAttrs, compLines, name, 3)
}

func firstNon(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func fmtLines(l []adLine) string {
	w := 0
	for _, x := range l {
		if len(x.k) > w {
			w = len(x.k)
		}
	}
	var b strings.Builder
	for _, x := range l {
		if x.v == "" {
			continue
		}
		fmt.Fprintf(&b, "%-*s  %s\n", w, x.k, x.v)
	}
	return b.String()
}

// rank puts an exact match of the name first.
func adRank(e adEntry, name string) int {
	n := strings.ToLower(name)
	if i := strings.LastIndexByte(n, '\\'); i >= 0 {
		n = n[i+1:]
	}
	for _, k := range []string{"samaccountname", "userprincipalname", "mail", "dnshostname", "name", "cn"} {
		if strings.EqualFold(strings.TrimSuffix(e.first(k), "$"), strings.TrimSuffix(n, "$")) {
			return 0
		}
	}
	return 1
}

func adSort(es []adEntry, name string) {
	sort.SliceStable(es, func(i, j int) bool {
		ri, rj := adRank(es[i], name), adRank(es[j], name)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(es[i].DN) < strings.ToLower(es[j].DN)
	})
}

// Show takes the commands in the type's comment.
func (a *ad) Show(ctx context.Context, cmd string) (string, error) {
	usage := errors.New("show user NAME | users NAME | computer NAME | computers NAME | group NAME | domain | locked | disabled | stale users|computers [DAYS]  (NAME: a sign-in name, mail address, display name or computer name, or the start of one)")
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	kind := strings.ToLower(f[1])
	name := strings.TrimSpace(strings.TrimPrefix(strings.Join(f[2:], " "), "user="))
	switch kind {
	case "domain":
		return a.showDomain(ctx)
	case "locked", "disabled", "stale":
		return a.showProblems(ctx, kind, f[2:])
	}
	if !adNameOK(name) {
		return "", usage
	}
	base, err := a.searchBase(ctx)
	if err != nil {
		return "", err
	}
	var filter []byte
	var attrs []string
	var lines func(adEntry) []adLine
	var noun string
	switch kind {
	case "user", "users":
		filter, attrs, lines, noun = adUserFilter(name), adUserAttrs, userLines, "user"
	case "computer", "computers":
		filter, attrs, lines, noun = adCompFilter(name), adCompAttrs, compLines, "computer"
	case "group":
		filter, attrs, lines, noun = adGroupFilter(name), adGroupAttrs, groupLines, "group"
	default:
		return "", usage
	}
	list := kind == "users" || kind == "computers"
	limit := adDetailMax + 1
	if list {
		limit = adListMax
	}
	es, cut, err := a.search(ctx, base, 2, filter, attrs, limit*3)
	if err != nil {
		return "", err
	}
	adSort(es, name)
	if len(es) == 0 {
		return "", fmt.Errorf("no %s matches %q", noun, name)
	}
	if len(es) > limit {
		es, cut = es[:limit], true
	}
	var b strings.Builder
	if list {
		for _, e := range es {
			l := lines(e)
			var parts []string
			for _, x := range l {
				switch x.k {
				case "Name", "Account", "Sign-in name", "Enabled", "DNS name":
					parts = append(parts, x.v)
				}
			}
			b.WriteString(strings.Join(parts, "  ") + "\n")
		}
	} else {
		for i, e := range es {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(fmtLines(lines(e)))
		}
	}
	if cut {
		b.WriteString("\nThere are more matches; give more of the name.\n")
	}
	return RedactText(b.String()), nil
}

func (a *ad) showDomain(ctx context.Context) (string, error) {
	r, err := a.root(ctx)
	if err != nil {
		return "", err
	}
	lvl := func(k string) string { return firstNon(adLevels[r.first(k)], r.first(k)) }
	return fmtLines([]adLine{{"Controller", r.first("dnsHostName")}, {"Domain", r.first("defaultNamingContext")}, {"Forest root", r.first("rootDomainNamingContext")},
		{"Domain level", lvl("domainFunctionality")}, {"Forest level", lvl("forestFunctionality")}, {"Controller level", lvl("domainControllerFunctionality")},
		{"Time", r.first("currentTime")}}), nil
}

const adStaleDefault = 90

// showProblems: accounts that need a look.
//
//	show locked                          users with a lockout time (the next sign-in that works clears it; one older than the lockout
//	                                     duration has expired)
//	show disabled                        disabled users that still belong to groups
//	show stale users|computers [DAYS]    enabled accounts that have not signed in for DAYS days (default 90; 1 to 3650), or never,
//	                                     and were created before that
func (a *ad) showProblems(ctx context.Context, kind string, args []string) (string, error) {
	base, err := a.searchBase(ctx)
	if err != nil {
		return "", err
	}
	person := []([]byte){fEq("objectCategory", "person"), fEq("objectClass", "user")}
	var filter []byte
	var attrs []string
	var line func(adEntry) string
	never := func(e adEntry) string { return firstNon(adFiletime(e.first("lastLogonTimestamp")), "never") }
	title := ""
	switch kind {
	case "locked":
		filter, attrs, title = fAnd(append(person, fGe("lockoutTime", "1"))...), adUserAttrs, "users with a lockout time"
		line = func(e adEntry) string {
			return fmt.Sprintf("%s  %s  locked since %s", firstNon(e.first("displayName"), e.first("cn")), e.first("sAMAccountName"), firstNon(adFiletime(e.first("lockoutTime")), "unknown"))
		}
	case "disabled":
		filter, attrs, title = fAnd(append(person, fBit("userAccountControl", 2), fPres("memberOf"))...), adUserAttrs, "disabled users that are still in groups"
		line = func(e adEntry) string {
			return fmt.Sprintf("%s  %s  %d groups  last sign-in %s", firstNon(e.first("displayName"), e.first("cn")), e.first("sAMAccountName"), len(e.Attrs["memberof"]), never(e))
		}
	default:
		days, what := adStaleDefault, ""
		for _, x := range args {
			switch w := strings.ToLower(x); {
			case w == "users" || w == "computers":
				what = w
			default:
				n, err := strconv.Atoi(w)
				if err != nil || n < 1 || n > 3650 {
					return "", errors.New("show stale users|computers [DAYS]: DAYS is 1 to 3650")
				}
				days = n
			}
		}
		if what == "" {
			return "", errors.New("show stale users|computers [DAYS]")
		}
		cut := time.Now().UTC().AddDate(0, 0, -days)
		ft := strconv.FormatInt((cut.Unix()+11644473600)*10000000, 10)
		class := person
		attrs = adUserAttrs
		if what == "computers" {
			class, attrs = [][]byte{fEq("objectClass", "computer")}, adCompAttrs
		}
		filter = fAnd(append(class, fNot(fBit("userAccountControl", 2)), fLe("whenCreated", cut.Format("20060102150405.0Z")),
			fOr(fLe("lastLogonTimestamp", ft), fNot(fPres("lastLogonTimestamp"))))...)
		title = fmt.Sprintf("enabled %s with no sign-in for %d days", what, days)
		line = func(e adEntry) string {
			return fmt.Sprintf("%s  %s  last sign-in %s", firstNon(e.first("displayName"), e.first("name"), e.first("cn")), e.first("sAMAccountName"), never(e))
		}
	}
	es, cut, err := a.search(ctx, base, 2, filter, attrs, adListMax*3)
	if err != nil {
		return "", err
	}
	if len(es) == 0 {
		return "None: no " + title + ".\n", nil
	}
	sort.SliceStable(es, func(i, j int) bool { // the longest without a sign-in first
		return firstNon(adFiletime(es[i].first("lastLogonTimestamp")), "0") < firstNon(adFiletime(es[j].first("lastLogonTimestamp")), "0")
	})
	if len(es) > adListMax {
		es, cut = es[:adListMax], true
	}
	var b strings.Builder
	for _, e := range es {
		b.WriteString(line(e) + "\n")
	}
	if cut {
		b.WriteString("\nThere are more; the longest without a sign-in are first only among those found.\n")
	}
	return RedactText(b.String()), nil
}

func fNot(f []byte) []byte { return tlv(0xa2, f) }
func fGe(attr, val string) []byte {
	return tlv(0xa5, tlv(tagOctets, []byte(attr)), tlv(tagOctets, []byte(val)))
}
func fLe(attr, val string) []byte {
	return tlv(0xa6, tlv(tagOctets, []byte(attr)), tlv(tagOctets, []byte(val)))
}

// fBit: the bits of mask are set in the numeric attribute (Active Directory's LDAP_MATCHING_RULE_BIT_AND).
func fBit(attr string, mask int) []byte {
	return tlv(0xa9, tlv(0x81, []byte("1.2.840.113556.1.4.803")), tlv(0x82, []byte(attr)), tlv(0x83, []byte(strconv.Itoa(mask))))
}
