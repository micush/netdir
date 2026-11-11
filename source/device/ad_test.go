package device

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// adStub is a directory written from RFC 4511: LDAPS, a simple bind, and searches with a filter it evaluates.
type adStub struct {
	mu       sync.Mutex
	searches []string // "base|attrs" of every search
	binds    int
	starttls bool
}

func adCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type adObj map[string][]string

const adBase = "DC=corp,DC=example,DC=com"

// adFT is a time as Active Directory writes it: 100 ns steps since 1601.
func adFT(t time.Time) string { return strconv.FormatInt((t.Unix()+11644473600)*10000000, 10) }

func adDir() map[string]adObj {
	recent := adFT(time.Now().Add(-48 * time.Hour))
	old := adFT(time.Now().AddDate(-2, 0, 0))
	return map[string]adObj{
		"CN=Joe Smith,CN=Users," + adBase: {"objectclass": {"top", "person", "user"}, "objectcategory": {"person"}, "cn": {"Joe Smith"}, "samaccountname": {"jsmith"}, "userprincipalname": {"jsmith@corp.example.com"},
			"mail": {"joe.smith@example.com"}, "displayname": {"Joe Smith"}, "title": {"Network engineer"}, "department": {"IT"}, "useraccountcontrol": {"66048"}, "pwdlastset": {"133700000000000000"},
			"lastlogontimestamp": {recent}, "memberof": {"CN=Domain Admins,CN=Users," + adBase, "CN=VPN Users,OU=Groups," + adBase}, "whencreated": {"20230105120000.0Z"},
			"manager": {"CN=Ann Boss,CN=Users," + adBase}, "unicodepwd": {"SECRET-HASH"}},
		"CN=Jsmithers,CN=Users," + adBase: {"objectclass": {"top", "person", "user"}, "objectcategory": {"person"}, "cn": {"Jsmithers"}, "samaccountname": {"jsmithers"}, "useraccountcontrol": {"514"},
			"lockouttime": {"133740000000000000"}},
		"CN=JSMITH-LAPTOP,OU=PCs," + adBase: {"objectclass": {"top", "person", "user", "computer"}, "objectcategory": {"computer"}, "cn": {"JSMITH-LAPTOP"}, "name": {"JSMITH-LAPTOP"}, "samaccountname": {"JSMITH-LAPTOP$"},
			"dnshostname": {"jsmith-laptop.corp.example.com"}, "operatingsystem": {"Windows 11 Enterprise"}, "operatingsystemversion": {"10.0 (22631)"}, "useraccountcontrol": {"4096"},
			"lastlogontimestamp": {recent}, "managedby": {"CN=Joe Smith,CN=Users," + adBase}, "ms-mcs-admpwd": {"LAPS-PASSWORD"}},
		"CN=Old Oldy,CN=Users," + adBase: {"objectclass": {"top", "person", "user"}, "objectcategory": {"person"}, "cn": {"Old Oldy"}, "samaccountname": {"ooldy"}, "useraccountcontrol": {"512"},
			"lastlogontimestamp": {old}, "whencreated": {"20180101000000.0Z"}},
		"CN=Gone Guy,CN=Users," + adBase: {"objectclass": {"top", "person", "user"}, "objectcategory": {"person"}, "cn": {"Gone Guy"}, "samaccountname": {"gguy"}, "useraccountcontrol": {"514"},
			"memberof": {"CN=Domain Admins,CN=Users," + adBase}, "lastlogontimestamp": {old}},
		"CN=OLD-PC,OU=PCs," + adBase: {"objectclass": {"top", "person", "user", "computer"}, "objectcategory": {"computer"}, "cn": {"OLD-PC"}, "name": {"OLD-PC"}, "samaccountname": {"OLD-PC$"},
			"useraccountcontrol": {"4096"}, "lastlogontimestamp": {old}, "whencreated": {"20190101000000.0Z"}},
		"CN=NEW-PC,OU=PCs," + adBase: {"objectclass": {"top", "person", "user", "computer"}, "objectcategory": {"computer"}, "cn": {"NEW-PC"}, "name": {"NEW-PC"}, "samaccountname": {"NEW-PC$"},
			"useraccountcontrol": {"4096"}, "whencreated": {"29990101000000.0Z"}},
		"CN=Domain Admins,CN=Users," + adBase: {"objectclass": {"top", "group"}, "cn": {"Domain Admins"}, "samaccountname": {"Domain Admins"}, "description": {"Designated administrators"},
			"member": {"CN=Joe Smith,CN=Users," + adBase, "CN=Ann Boss,CN=Users," + adBase}},
	}
}

func (s *adStub) eval(f []byte, o adObj) bool {
	tag, c, _, _ := next(f)
	get := func(a string) []string { return o[strings.ToLower(a)] }
	switch tag {
	case 0xa0, 0xa1:
		for len(c) > 0 {
			var sub []byte
			t, cc, rest, _ := next(c)
			sub = append(append([]byte{t}, berLen(len(cc))...), cc...)
			c = rest
			ok := s.eval(sub, o)
			if tag == 0xa0 && !ok {
				return false
			}
			if tag == 0xa1 && ok {
				return true
			}
		}
		return tag == 0xa0
	case 0xa3:
		_, a, rest, _ := next(c)
		_, v, _, _ := next(rest)
		for _, x := range get(string(a)) {
			if strings.EqualFold(x, string(v)) {
				return true
			}
		}
	case 0xa4:
		_, a, rest, _ := next(c)
		_, seq, _, _ := next(rest)
		_, init, _, _ := next(seq)
		for _, x := range get(string(a)) {
			if strings.HasPrefix(strings.ToLower(x), strings.ToLower(string(init))) {
				return true
			}
		}
	case 0x87:
		return len(get(string(c))) > 0
	case 0xa2:
		t, cc, _, _ := next(c)
		return !s.eval(append(append([]byte{t}, berLen(len(cc))...), cc...), o)
	case 0xa5, 0xa6:
		_, a, rest, _ := next(c)
		_, v, _, _ := next(rest)
		for _, x := range get(string(a)) {
			xi, e1 := strconv.ParseInt(x, 10, 64)
			vi, e2 := strconv.ParseInt(string(v), 10, 64)
			cmp := strings.Compare(x, string(v))
			if e1 == nil && e2 == nil {
				cmp = 0
				if xi < vi {
					cmp = -1
				} else if xi > vi {
					cmp = 1
				}
			}
			if tag == 0xa5 && cmp >= 0 || tag == 0xa6 && cmp <= 0 {
				return true
			}
		}
	case 0xa9: // extensible match, the bit-and rule
		_, rule, r1, _ := next(c)
		_, a, r2, _ := next(r1)
		_, v, _, _ := next(r2)
		if string(rule) != "1.2.840.113556.1.4.803" {
			return false
		}
		m, _ := strconv.ParseInt(string(v), 10, 64)
		for _, x := range get(string(a)) {
			if xi, err := strconv.ParseInt(x, 10, 64); err == nil && xi&m == m {
				return true
			}
		}
	}
	return false
}

func (s *adStub) serve(t *testing.T, conn net.Conn, cert tls.Certificate, wantPW string) {
	defer conn.Close()
	var rd *bufio.Reader
	if !s.starttls {
		c := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		conn, rd = c, bufio.NewReader(c)
	} else {
		rd = bufio.NewReader(conn)
	}
	dir := adDir()
	for {
		tag, c, err := readBER(rd)
		if err != nil || tag != tagSeq {
			return
		}
		_, idb, rest, _ := next(c)
		id := parseInt(idb)
		op, body, _, _ := next(rest)
		reply := func(op byte, content ...[]byte) {
			_, _ = conn.Write(tlv(tagSeq, berInt(id), tlv(op, content...)))
		}
		res := func(code int, diag string) [][]byte {
			return [][]byte{{0x0a, 0x01, byte(code)}, tlv(tagOctets, nil), tlv(tagOctets, []byte(diag))}
		}
		switch op {
		case 0x77: // StartTLS
			reply(0x78, res(0, "")...)
			c := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			conn, rd = c, bufio.NewReader(c)
		case 0x60:
			s.mu.Lock()
			s.binds++
			s.mu.Unlock()
			_, _, r2, _ := next(body)  // version
			_, name, r3, _ := next(r2) // name
			_, pw, _, _ := next(r3)    // simple
			if string(name) == "svc@corp.example.com" && string(pw) == wantPW {
				reply(0x61, res(0, "")...)
			} else {
				reply(0x61, res(49, "80090308: LdapErr: DSID-0C09044E, data 52e")...)
			}
		case 0x63:
			_, base, r2, _ := next(body)
			_, scope, r3, _ := next(r2)
			_, _, r4, _ := next(r3) // deref
			_, _, r5, _ := next(r4) // size
			_, _, r6, _ := next(r5) // time
			_, _, r7, _ := next(r6) // typesOnly
			ft, fc, r8, _ := next(r7)
			filter := append(append([]byte{ft}, berLen(len(fc))...), fc...)
			_, al, _, _ := next(r8)
			var attrs []string
			for len(al) > 0 {
				var a []byte
				_, a, al, _ = next(al)
				attrs = append(attrs, string(a))
			}
			s.mu.Lock()
			s.searches = append(s.searches, string(base)+"|"+strings.Join(attrs, ","))
			s.mu.Unlock()
			if len(scope) == 1 && scope[0] == 0 && string(base) == "" { // root DSE
				vals := map[string]string{"defaultNamingContext": adBase, "dnsHostName": "dc1.corp.example.com", "domainFunctionality": "7", "forestFunctionality": "7", "domainControllerFunctionality": "7",
					"rootDomainNamingContext": adBase, "currentTime": "20261110180000.0Z"}
				var as [][]byte
				for _, a := range attrs {
					if v, ok := vals[a]; ok {
						as = append(as, tlv(tagSeq, tlv(tagOctets, []byte(a)), tlv(0x31, tlv(tagOctets, []byte(v)))))
					}
				}
				reply(0x64, tlv(tagOctets, nil), tlv(tagSeq, as...))
				reply(0x65, res(0, "")...)
				continue
			}
			for dn, o := range dir {
				if !s.eval(filter, o) {
					continue
				}
				var as [][]byte
				for _, a := range attrs {
					if v := o[strings.ToLower(a)]; len(v) > 0 {
						var vs [][]byte
						for _, x := range v {
							vs = append(vs, tlv(tagOctets, []byte(x)))
						}
						as = append(as, tlv(tagSeq, tlv(tagOctets, []byte(a)), tlv(0x31, vs...)))
					}
				}
				reply(0x64, tlv(tagOctets, []byte(dn)), tlv(tagSeq, as...))
			}
			reply(0x65, res(0, "")...)
		case 0x42:
			return
		}
	}
}

func adServer(t *testing.T, starttls bool) (Device, *adStub) {
	t.Helper()
	cert := adCert(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	st := &adStub{starttls: starttls}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go st.serve(t, c, cert, "S3CRET")
		}
	}()
	h, p, _ := net.SplitHostPort(l.Addr().String())
	pn, _ := strconv.Atoi(p)
	d := Device{Name: "dc1", Platform: "ad", Address: h, Port: pn, Insecure: true}
	if starttls {
		d.Options = map[string]string{"starttls": "true"}
	}
	return d, st
}

func TestADLookups(t *testing.T) {
	for _, starttls := range []bool{false, true} {
		d, st := adServer(t, starttls)
		drv, err := Open(d, Credential{Name: "svc", Username: "svc@corp.example.com", Password: "S3CRET"})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		f, err := drv.Facts(ctx)
		leakAdd("ad", "facts", f, err)
		if err != nil || f.Hostname != "dc1.corp.example.com" || f.Vendor != "Microsoft" || !strings.Contains(f.OSVersion, "2016") {
			t.Fatalf("facts (starttls %v): %v %+v", starttls, err, f)
		}
		out, err := drv.Show(ctx, "show user jsmith")
		leakAdd("ad", "show user", out, err)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Joe Smith", "jsmith@corp.example.com", "Enabled        yes", "Network engineer", "Domain Admins, VPN Users", "Ann Boss", "Sign-in expires never", "Last sign-in"} {
			if !strings.Contains(out, want) && !strings.Contains(strings.Join(strings.Fields(out), " "), strings.Join(strings.Fields(want), " ")) {
				t.Errorf("show user lacks %q:\n%s", want, out)
			}
		}
		// the exact match comes before the one that only starts with the name
		if i, j := strings.Index(out, "Account       jsmith\n"), strings.Index(out, "Jsmithers"); j >= 0 && i > j || i < 0 && !strings.Contains(out, "jsmith\n") {
			t.Errorf("ranking:\n%s", out)
		}
		if strings.Contains(out, "SECRET-HASH") {
			t.Error("a password hash was shown")
		}
		out, err = drv.Show(ctx, `show user CORP\jsmithers`)
		if err != nil || !strings.Contains(out, "Enabled        no") && !strings.Contains(strings.Join(strings.Fields(out), " "), "Enabled no") || !strings.Contains(out, "Locked out") {
			t.Errorf("a disabled, locked user: %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show users jsm")
		if err != nil || strings.Count(out, "\n") != 2 {
			t.Errorf("show users: %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show computer jsmith-laptop.corp.example.com")
		leakAdd("ad", "show computer", out, err)
		if err != nil || !strings.Contains(out, "JSMITH-LAPTOP") || !strings.Contains(out, "Windows 11 Enterprise 10.0 (22631)") || !strings.Contains(out, "Managed by") || strings.Contains(out, "LAPS-PASSWORD") {
			t.Errorf("show computer: %v\n%s", err, out)
		}
		if out, err = drv.Show(ctx, "show computer JSMITH-LAPTOP$"); err != nil || !strings.Contains(out, "JSMITH-LAPTOP") {
			t.Errorf("a computer by its account name: %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show group domain admins")
		if err != nil || !strings.Contains(out, "Members") || !strings.Contains(out, "Ann Boss, Joe Smith") {
			t.Errorf("show group: %v\n%s", err, out)
		}
		if out, err = drv.Show(ctx, "show domain"); err != nil || !strings.Contains(out, "dc1.corp.example.com") {
			t.Errorf("show domain: %v\n%s", err, out)
		}
		if _, err = drv.Show(ctx, "show user nobody"); err == nil || !strings.Contains(err.Error(), "no user matches") {
			t.Errorf("no such user: %v", err)
		}
		// a name is a value, never filter text; and only the listed attributes are asked for
		before := len(st.searches)
		for _, bad := range []string{"show user a)(objectClass=*", "show user *", "show user x;y", "show user ", "show frob x", "show user a|b"} {
			if _, err := drv.Show(ctx, bad); err == nil {
				t.Errorf("%q was accepted", bad)
			}
		}
		if len(st.searches) != before {
			t.Errorf("a refused name reached the directory: %v", st.searches[before:])
		}
		for _, s := range st.searches {
			for _, w := range []string{"unicodePwd", "msLAPS", "ms-Mcs", "ntSecurityDescriptor", "userPassword", "objectSid"} {
				if strings.Contains(strings.ToLower(s), strings.ToLower(w)) {
					t.Errorf("a secret attribute was asked for: %s", s)
				}
			}
		}
		// accounts that need a look
		out, err = drv.Show(ctx, "show locked")
		if err != nil || !strings.Contains(out, "jsmithers") || strings.Contains(out, "jsmith  ") {
			t.Errorf("show locked: %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show disabled")
		if err != nil || !strings.Contains(out, "gguy") || !strings.Contains(out, "1 groups") || strings.Contains(out, "jsmithers") {
			t.Errorf("show disabled (still in groups; one without groups is not listed): %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show stale computers")
		if err != nil || !strings.Contains(out, "OLD-PC") || strings.Contains(out, "JSMITH-LAPTOP") || strings.Contains(out, "NEW-PC") {
			t.Errorf("show stale computers: %v\n%s", err, out)
		}
		out, err = drv.Show(ctx, "show stale users 30")
		if err != nil || !strings.Contains(out, "ooldy") || strings.Contains(out, "jsmith ") || strings.Contains(out, "gguy") {
			t.Errorf("show stale users (an old account, not a recent one, not a disabled one): %v\n%s", err, out)
		}
		for _, bad := range []string{"show stale", "show stale users 0", "show stale users x", "show stale users 99999"} {
			if _, err := drv.Show(ctx, bad); err == nil {
				t.Errorf("%q was accepted", bad)
			}
		}
		// as records for the troubleshooting
		l := bareDriver(drv).(DirectoryLooker)
		us, err := l.DirUsers(ctx, "jsmith@corp.example.com")
		if err != nil || len(us) == 0 || us[0]["account"] != "jsmith" || us[0]["enabled"] != true || us[0]["groups"] != "Domain Admins, VPN Users" {
			t.Errorf("DirUsers: %v %v", err, us)
		}
		cs, err := l.DirComputers(ctx, "jsmith-laptop")
		if err != nil || len(cs) != 1 || cs[0]["dns_name"] != "jsmith-laptop.corp.example.com" {
			t.Errorf("DirComputers: %v %v", err, cs)
		}
		if st.binds != 1 {
			t.Errorf("%d binds for one driver", st.binds)
		}
		if _, err := drv.(RawChanger).RawChange(ctx, Raw{Method: "POST", Path: "/x"}, false); err == nil {
			t.Error("Active Directory was changed")
		}
		drv.Close(ctx)
	}
}

func TestADLogin(t *testing.T) {
	d, _ := adServer(t, false)
	if _, err := Open(d, Credential{Name: "svc", Username: "svc@corp.example.com"}); err == nil {
		t.Error("a login without a password was opened (an unauthenticated bind)")
	}
	drv, err := Open(d, Credential{Name: "svc", Username: "svc@corp.example.com", Password: "WRONG-PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = drv.Facts(context.Background())
	if err == nil || strings.Contains(err.Error(), "WRONG-PASSWORD") || !strings.Contains(err.Error(), "refused the login") {
		t.Errorf("a wrong password: %v", err)
	}
	// plain LDAP is never spoken: a directory that does not do TLS is an error, not a clear-text bind
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		if c != nil {
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			if n > 0 && strings.Contains(string(buf[:n]), "S3CRET") {
				t.Error("the password was sent without TLS")
			}
			c.Close()
		}
	}()
	h, p, _ := net.SplitHostPort(l.Addr().String())
	pn, _ := strconv.Atoi(p)
	drv, _ = Open(Device{Name: "x", Platform: "ad", Address: h, Port: pn, Insecure: true}, Credential{Name: "svc", Username: "u", Password: "S3CRET"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := drv.Facts(ctx); err == nil {
		t.Error("no TLS, no error")
	}
}
