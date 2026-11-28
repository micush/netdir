package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"netdir/internal/core"
)

// A small directory server that speaks enough LDAP for the client: simple bind, search (and, or, not, equality and the
// nested-group matching rule), StartTLS and unbind.

type fakeUser struct {
	dn, sam, upn, pw string
	disabled         bool
	computer         bool
	groups           map[string]bool // lower-case DNs of every group it is in, nested ones included
}

type fakeLDAP struct {
	t              *testing.T
	ln             net.Listener
	cfg            *tls.Config
	mu             sync.Mutex
	users          []*fakeUser
	groups         map[string]string // sAMAccountName -> DN
	svcDN, svcPW   string
	svcBinds       int
	userBinds      int
	refuseStartTLS bool
	tlsFirst       bool
}

const (
	fakeRW = "CN=dns-admins,OU=Groups,DC=example,DC=lan"
	fakeRO = "CN=dns-readers,OU=Groups,DC=example,DC=lan"
)

func newFakeLDAP(t *testing.T, tlsFirst bool) *fakeLDAP {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f := &fakeLDAP{t: t, tlsFirst: tlsFirst, svcDN: "CN=svc,OU=Service,DC=example,DC=lan", svcPW: "svcpw",
		groups: map[string]string{"dns-admins": fakeRW, "dns-readers": fakeRO},
		cfg:    &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	add := func(sam, pw string, groups ...string) *fakeUser {
		u := &fakeUser{dn: "CN=" + sam + ",OU=People,DC=example,DC=lan", sam: sam, upn: sam + "@example.lan", pw: pw, groups: map[string]bool{}}
		for _, g := range groups {
			u.groups[strings.ToLower(g)] = true
		}
		f.users = append(f.users, u)
		return u
	}
	add("alice", "alicepw", fakeRW)
	add("bob", "bobpw", fakeRO)
	add("carol", "carolpw")
	add("dave", "davepw", fakeRW).disabled = true
	add("erin", "erinpw", fakeRW) // in the group through another group
	add("pc1$", "pcpw", fakeRW).computer = true
	add("twin", "twinpw", fakeRW)
	add("twin", "twinpw", fakeRW).dn = "CN=twin2,OU=People,DC=example,DC=lan"
	add("dora", "dorapw", fakeRW)
	add("rob", "robpw", fakeRO)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(f.Stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeLDAP) Stop() { f.ln.Close() }

func (f *fakeLDAP) addr() string {
	s := "ldap://"
	if f.tlsFirst {
		s = "ldaps://"
	}
	return s + f.ln.Addr().String()
}

func (f *fakeLDAP) config() core.LDAPConfig {
	return core.LDAPConfig{LDAPServers: []string{f.addr()}, LDAPSkipVerify: true, LDAPBindDN: f.svcDN, LDAPBindPassword: f.svcPW,
		LDAPBaseDN: "DC=example,DC=lan", LDAPRWGroup: fakeRW, LDAPROGroup: "dns-readers"}
}

func lresult(tag byte, code int, diag string) []byte {
	return core.Tlv(tag, core.BerInt(0x0a, code), core.BerOctet(""), core.BerOctet(diag))
}

type fakeEntry struct {
	dn      string
	classes []string
	sam     string
	upn     string
	uac     string
	chain   map[string]bool
}

func (f *fakeLDAP) entries() []*fakeEntry {
	var out []*fakeEntry
	for _, u := range f.users {
		e := &fakeEntry{dn: u.dn, classes: []string{"top", "person", "user"}, sam: u.sam, upn: u.upn, uac: "512", chain: u.groups}
		if u.computer {
			e.classes = append(e.classes, "computer")
		}
		if u.disabled {
			e.uac = "514"
		}
		out = append(out, e)
	}
	for sam, dn := range f.groups {
		out = append(out, &fakeEntry{dn: dn, classes: []string{"top", "group"}, sam: sam})
	}
	return out
}

func evalFilter(n *core.BerNode, e *fakeEntry) bool {
	switch n.Tag {
	case 0xA0:
		for _, k := range n.Kids {
			if !evalFilter(k, e) {
				return false
			}
		}
		return true
	case 0xA1:
		for _, k := range n.Kids {
			if evalFilter(k, e) {
				return true
			}
		}
		return false
	case 0xA2:
		return !evalFilter(n.Kids[0], e)
	case 0xA3:
		attr, val := strings.ToLower(string(n.Kids[0].Val)), string(n.Kids[1].Val)
		switch attr {
		case "objectclass":
			for _, c := range e.classes {
				if strings.EqualFold(c, val) {
					return true
				}
			}
		case "samaccountname":
			return strings.EqualFold(e.sam, val)
		case "userprincipalname":
			return e.upn != "" && strings.EqualFold(e.upn, val)
		}
		return false
	case 0xA9:
		var rule, attr, val string
		for _, k := range n.Kids {
			switch k.Tag {
			case 0x81:
				rule = string(k.Val)
			case 0x82:
				attr = string(k.Val)
			case 0x83:
				val = string(k.Val)
			}
		}
		return rule == "1.2.840.113556.1.4.1941" && strings.EqualFold(attr, "memberOf") && e.chain[strings.ToLower(val)]
	}
	return false
}

func (f *fakeLDAP) serve(raw net.Conn) {
	var c net.Conn = raw
	defer func() { c.Close() }()
	if f.tlsFirst {
		c = tls.Server(raw, f.cfg)
	}
	br := bufio.NewReader(c)
	bound := false
	send := func(id int, op []byte) { c.Write(core.Tlv(0x30, core.BerInt(0x02, id), op)) }
	for {
		id, op, err := core.ReadMessage(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		switch op.Tag {
		case 0x77: // StartTLS
			f.mu.Unlock()
			if f.refuseStartTLS {
				send(id, lresult(0x78, 2, "no"))
				continue
			}
			send(id, lresult(0x78, 0, ""))
			c = tls.Server(raw, f.cfg)
			br = bufio.NewReader(c)
			continue
		case 0x60: // bind
			dn, pw := string(op.Kids[1].Val), string(op.Kids[2].Val)
			ok := false
			if dn == f.svcDN {
				f.svcBinds++
				ok = pw == f.svcPW
				bound = ok
			} else {
				f.userBinds++
				for _, u := range f.users {
					who := strings.EqualFold(u.dn, dn) || strings.EqualFold(u.upn, dn) || strings.EqualFold("EXAMPLE\\"+u.sam, dn)
					if !who && strings.EqualFold(u.sam+"@example.lan", dn) { // account name @ domain, only when no account has it as its UPN (as Active Directory does)
						who = true
						for _, o := range f.users {
							if strings.EqualFold(o.upn, dn) {
								who = false
							}
						}
					}
					if who && u.pw == pw && pw != "" && !u.disabled {
						ok = true
					}
				}
			}
			if ok {
				if dn != f.svcDN {
					bound = true // a person who bound may read the directory too
				}
				send(id, lresult(0x61, 0, ""))
			} else {
				send(id, lresult(0x61, 49, "invalid credentials"))
			}
		case 0x63: // search
			if !bound {
				send(id, lresult(0x65, 50, "bind first"))
				break
			}
			base, scope, limit, filter, attrs := string(op.Kids[0].Val), core.BerToInt(op.Kids[1]), core.BerToInt(op.Kids[3]), op.Kids[6], op.Kids[7]
			var hits []*fakeEntry
			for _, e := range f.entries() {
				if scope == core.LdapScopeBase && !strings.EqualFold(e.dn, base) {
					continue
				}
				if evalFilter(filter, e) {
					hits = append(hits, e)
				}
			}
			code := 0
			if limit > 0 && len(hits) > limit {
				hits, code = hits[:limit], 4
			}
			for _, e := range hits {
				var as [][]byte
				for _, a := range attrs.Kids {
					if strings.EqualFold(string(a.Val), "sAMAccountName") && e.sam != "" {
						as = append(as, core.Tlv(0x30, core.BerOctet("sAMAccountName"), core.Tlv(0x31, core.BerOctet(e.sam))))
					}
					if strings.EqualFold(string(a.Val), "userPrincipalName") && e.upn != "" {
						as = append(as, core.Tlv(0x30, core.BerOctet("userPrincipalName"), core.Tlv(0x31, core.BerOctet(e.upn))))
					}
					if strings.EqualFold(string(a.Val), "userAccountControl") && e.uac != "" && e.sam != "" && !strings.Contains(strings.Join(e.classes, ","), "group") {
						as = append(as, core.Tlv(0x30, core.BerOctet("userAccountControl"), core.Tlv(0x31, core.BerOctet(e.uac))))
					}
				}
				send(id, core.Tlv(0x64, core.BerOctet(e.dn), core.Tlv(0x30, as...)))
			}
			send(id, lresult(0x65, code, ""))
		case 0x42:
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
	}
}

func TestLDAPWebLogin(t *testing.T) {
	f := newFakeLDAP(t, true)
	e := newWebEnv(t)
	p := core.DefaultWeb()
	p.MaxFailedLogins = 50
	p.LDAPConfig = f.config()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.Policy.Store(&p)
	// a directory account that the host does not know
	if r := e.login("dora", "dorapw"); r.code != 200 || r.body["read_only"] != false {
		t.Fatalf("dora: %d %v", r.code, r.body)
	}
	session := func() resp { return e.do("GET", "/api/session", nil, withAuth(e, false)) }
	if r := session(); r.code != 200 || r.body["user"] != "dora" {
		t.Fatalf("session: %d %v", r.code, r.body)
	}
	age := func() {
		e.ws.Mu.Lock()
		for _, s := range e.ws.Sessions {
			s.Checked = time.Now().Add(-time.Hour)
		}
		e.ws.Mu.Unlock()
	}
	// the read-only group gives a read-only session
	if r := e.login("rob", "robpw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("rob: %d %v", r.code, r.body)
	}
	// a wrong password, and a host account, still behave as before
	if r := e.login("dora", "wrong"); r.code != 401 {
		t.Fatalf("wrong password: %d", r.code)
	}
	binds := f.svcBinds
	if r := e.login("alice", "pw"); r.code != 200 {
		t.Fatalf("host account: %d", r.code)
	}
	if f.svcBinds != binds {
		t.Fatal("the directory was asked about a host account")
	}
	// removed from the group: the session ends at the next check; the directory unreachable: it stays
	e.login("dora", "dorapw")
	f.mu.Lock()
	for _, u := range f.users {
		if u.sam == "dora" {
			u.groups = map[string]bool{}
		}
	}
	f.mu.Unlock()
	age()
	if r := session(); r.code != 401 {
		t.Fatalf("after removal: %d", r.code)
	}
	e.login("rob", "robpw")
	f.Stop()
	age()
	if r := session(); r.code != 200 {
		t.Fatalf("directory down: %d", r.code)
	}
	// the Test button: needs a full-access session, says what happened
	e.login("alice", "pw")
	f2 := newFakeLDAP(t, true)
	q := *e.ws.Policy.Load()
	q.LDAPConfig = f2.config()
	e.ws.Policy.Store(&q)
	r := e.do("POST", "/api/ldap/test", map[string]string{"username": "bob", "password": "bobpw"}, withAuth(e, true))
	d, _ := r.body["data"].(map[string]any)
	if r.code != 200 || d["ok"] != true || d["read_only"] != true || len(d["steps"].([]any)) < 3 {
		t.Fatalf("test: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/ldap/test", map[string]string{}, withAuth(e, true)); r.code != 200 || r.body["data"].(map[string]any)["ok"] != true {
		t.Fatalf("test without a user: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/ldap/test", map[string]string{"username": "bob"}, func(r *http.Request) {}); r.code != 401 {
		t.Fatalf("test without a session: %d", r.code)
	}
}

func TestLDAPWebNoServiceAccount(t *testing.T) {
	f := newFakeLDAP(t, true)
	e := newWebEnv(t)
	p := core.DefaultWeb()
	p.MaxFailedLogins = 50
	p.LDAPConfig = f.config()
	p.LDAPBindDN, p.LDAPBindPassword = "", ""
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.Policy.Store(&p)
	if r := e.login("dora", "dorapw"); r.code != 200 || r.body["read_only"] != false {
		t.Fatalf("dora: %d %v", r.code, r.body)
	}
	if r := e.login("rob", "robpw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("rob: %d %v", r.code, r.body)
	}
	// a session cannot be rechecked, so it stays even when the directory would now refuse it
	for _, u := range f.users {
		if u.sam == "dora" {
			u.disabled = true
		}
	}
	e.ws.Mu.Lock()
	for _, s := range e.ws.Sessions {
		s.Checked = time.Now().Add(-time.Hour)
	}
	e.ws.Mu.Unlock()
	if r := e.do("GET", "/api/session", nil, withAuth(e, false)); r.code != 200 {
		t.Fatalf("session was ended without a service account: %d", r.code)
	}
	if f.svcBinds != 0 {
		t.Fatalf("service account used %d times", f.svcBinds)
	}
	// the Test button needs a password in this mode
	e.login("alice", "pw")
	r := e.do("POST", "/api/ldap/test", map[string]any{"username": "rob"}, withAuth(e, true))
	d, _ := r.body["data"].(map[string]any)
	if r.code != 200 || d["ok"] != false || !strings.Contains(fmt.Sprint(d["steps"]), "password") {
		t.Fatalf("test without a password: %d %v", r.code, r.body)
	}
	r = e.do("POST", "/api/ldap/test", map[string]any{"username": "rob", "password": "robpw"}, withAuth(e, true))
	if d, _ = r.body["data"].(map[string]any); r.code != 200 || d["ok"] != true || d["read_only"] != true {
		t.Fatalf("test with a password: %d %v", r.code, r.body)
	}
}
