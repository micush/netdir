package core

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
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

func (f *fakeLDAP) config() LDAPConfig {
	return LDAPConfig{LDAPServers: []string{f.addr()}, LDAPSkipVerify: true, LDAPBindDN: f.svcDN, LDAPBindPassword: f.svcPW,
		LDAPBaseDN: "DC=example,DC=lan", LDAPRWGroup: fakeRW, LDAPROGroup: "dns-readers"}
}

func lresult(tag byte, code int, diag string) []byte {
	return Tlv(tag, BerInt(0x0a, code), BerOctet(""), BerOctet(diag))
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

func evalFilter(n *BerNode, e *fakeEntry) bool {
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
	send := func(id int, op []byte) { c.Write(Tlv(0x30, BerInt(0x02, id), op)) }
	for {
		id, op, err := ReadMessage(br)
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
			base, scope, limit, filter, attrs := string(op.Kids[0].Val), BerToInt(op.Kids[1]), BerToInt(op.Kids[3]), op.Kids[6], op.Kids[7]
			var hits []*fakeEntry
			for _, e := range f.entries() {
				if scope == LdapScopeBase && !strings.EqualFold(e.dn, base) {
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
						as = append(as, Tlv(0x30, BerOctet("sAMAccountName"), Tlv(0x31, BerOctet(e.sam))))
					}
					if strings.EqualFold(string(a.Val), "userPrincipalName") && e.upn != "" {
						as = append(as, Tlv(0x30, BerOctet("userPrincipalName"), Tlv(0x31, BerOctet(e.upn))))
					}
					if strings.EqualFold(string(a.Val), "userAccountControl") && e.uac != "" && e.sam != "" && !strings.Contains(strings.Join(e.classes, ","), "group") {
						as = append(as, Tlv(0x30, BerOctet("userAccountControl"), Tlv(0x31, BerOctet(e.uac))))
					}
				}
				send(id, Tlv(0x64, BerOctet(e.dn), Tlv(0x30, as...)))
			}
			send(id, lresult(0x65, code, ""))
		case 0x42:
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
	}
}

func TestLDAPFind(t *testing.T) {
	f := newFakeLDAP(t, true)
	// erin is in the group through another group, which the chain rule sees (the fake keeps the flattened set)
	cfg := f.config()
	for _, c := range []struct {
		user, pw string
		ok, ro   bool
	}{
		{"alice", "alicepw", true, false},
		{"EXAMPLE\\alice", "alicepw", true, false}, // DOMAIN\name
		{"alice@example.lan", "alicepw", true, false},
		{"ALICE", "alicepw", true, false},
		{"bob", "bobpw", true, true},
		{"erin", "erinpw", true, false},
		{"alice", "wrong", false, false},
		{"carol", "carolpw", false, false},      // in no group
		{"dave", "davepw", false, false},        // disabled
		{"pc1$", "pcpw", false, false},          // a computer account is not a person
		{"twin", "twinpw", false, false},        // two accounts with the name
		{"nobody", "x", false, false},           // no such account
		{"*)(objectClass=*", "x", false, false}, // filter characters are only a name that does not exist
		{"alice", "", false, false},             // an empty password is never a login
	} {
		before := f.userBinds
		o := cfg.LdapFind(c.user, c.pw, true)
		if o.OK != c.ok || (c.ok && o.ReadOnly != c.ro) {
			t.Errorf("%q: ok=%v ro=%v, want ok=%v ro=%v (%v)", c.user, o.OK, o.ReadOnly, c.ok, c.ro, o.Steps)
		}
		if o.Failed {
			t.Errorf("%q: reported as a directory failure: %v", c.user, o.Steps)
		}
		if c.pw == "" && f.userBinds != before {
			t.Errorf("an empty password was sent to the server")
		}
	}
	// the recheck of a session asks without a password
	if o := cfg.LdapFind("bob", "", false); !o.OK || !o.ReadOnly {
		t.Errorf("recheck: %v", o.Steps)
	}
	// a disabled account is refused by the lookup itself (a recheck has no password to fail)
	if o := cfg.LdapFind("dave", "", false); o.OK {
		t.Errorf("a disabled account passed the recheck: %v", o.Steps)
	}
	// a wrong service account is a settings problem, not an answer about a person
	bad := cfg
	bad.LDAPBindPassword = "nope"
	if o := bad.LdapFind("alice", "alicepw", true); o.OK || !o.Failed {
		t.Errorf("wrong bind password: %v", o.Steps)
	}
	// a server that is gone is a failure too (the session stays)
	f.Stop()
	if o := cfg.LdapFind("alice", "", false); o.OK || !o.Failed {
		t.Errorf("server down: %v", o.Steps)
	}
}

func TestLDAPStartTLSAndCertificates(t *testing.T) {
	// ldap:// with StartTLS
	f := newFakeLDAP(t, false)
	cfg := f.config()
	if o := cfg.LdapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("StartTLS: %v", o.Steps)
	}
	// a server that will not start TLS is not given the password, or the service account's
	g := newFakeLDAP(t, false)
	g.refuseStartTLS = true
	c2 := g.config()
	if o := c2.LdapFind("alice", "alicepw", true); o.OK || g.svcBinds != 0 || g.userBinds != 0 {
		t.Fatalf("StartTLS refused: ok=%v binds=%d/%d %v", o.OK, g.svcBinds, g.userBinds, o.Steps)
	}
	// certificate checking: a self-signed certificate is refused unless the checkbox is on
	h := newFakeLDAP(t, true)
	c3 := h.config()
	c3.LDAPSkipVerify = false
	if o := c3.LdapFind("alice", "alicepw", true); o.OK || !o.Failed || h.svcBinds != 0 {
		t.Fatalf("self-signed certificate was accepted: %v", o.Steps)
	}
	c3.LDAPSkipVerify = true
	if o := c3.LdapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("with the checkbox on: %v", o.Steps)
	}
	// the first server is down: the second answers
	c4 := h.config()
	c4.LDAPServers = []string{"ldaps://127.0.0.1:1", h.addr()}
	if o := c4.LdapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("fallback server: %v", o.Steps)
	}
}

// Without a service account each person binds as themselves.
func TestLDAPNoServiceAccount(t *testing.T) {
	f := newFakeLDAP(t, true)
	cfg := f.config()
	cfg.LDAPBindDN, cfg.LDAPBindPassword = "", ""
	if !cfg.Enabled() || cfg.HasBind() {
		t.Fatal("a configuration without a bind account is not enabled")
	}
	for _, c := range []struct {
		user, pw string
		ok, ro   bool
	}{
		{"alice", "alicepw", true, false},
		{"EXAMPLE\\alice", "alicepw", true, false},
		{"alice@example.lan", "alicepw", true, false},
		{"bob", "bobpw", true, true},
		{"erin", "erinpw", true, false},
		{"alice", "wrong", false, false},
		{"carol", "carolpw", false, false}, // in no group
		{"dave", "davepw", false, false},   // disabled: the directory refuses the bind
		{"pc1$", "pcpw", false, false},     // a computer account
		{"twin", "twinpw", false, false},   // two accounts with the name
		{"nobody", "x", false, false},
		{"alice", "", false, false},
	} {
		before := f.userBinds
		o := cfg.LdapFind(c.user, c.pw, true)
		if o.OK != c.ok || (c.ok && o.ReadOnly != c.ro) {
			t.Errorf("%q: ok=%v ro=%v, want ok=%v ro=%v (%v)", c.user, o.OK, o.ReadOnly, c.ok, c.ro, o.Steps)
		}
		if o.Failed {
			t.Errorf("%q: reported as a directory failure: %v", c.user, o.Steps)
		}
		if c.pw == "" && f.userBinds != before {
			t.Errorf("an empty password was sent to the server")
		}
	}
	if f.svcBinds != 0 {
		t.Errorf("the service account was used %d times", f.svcBinds)
	}
	// a session cannot be rechecked: asking without a password is refused, and says why
	if o := cfg.LdapFind("alice", "", false); o.OK || !o.Failed {
		t.Errorf("recheck without a service account: %v", o.Steps)
	}
	// a service account without its password (or the reverse) is half set up, so off
	half := cfg
	half.LDAPBindDN = "CN=svc,DC=x"
	if half.Enabled() {
		t.Error("a bind account without a password is enabled")
	}
	// the entry read back must be the account that signed in: twin2 shares a name but not the bind identity
	tw := newFakeLDAP(t, true)
	for _, u := range tw.users {
		if u.dn == "CN=twin2,OU=People,DC=example,DC=lan" {
			u.sam, u.upn = "other", "other@example.lan"
		}
	}
	tc := tw.config()
	tc.LDAPBindDN, tc.LDAPBindPassword = "", ""
	if o := tc.LdapFind("twin", "twinpw", true); !o.OK {
		t.Errorf("a unique twin should sign in: %v", o.Steps)
	}
	// somebody else's password must not sign in as the account the name finds: "alice" binds as alice@example.lan, which
	// here belongs to another account (ally) than the one whose account name is alice
	for _, u := range tw.users {
		if u.sam == "alice" {
			u.upn = "alice2@example.lan"
		}
	}
	tw.users = append(tw.users, &fakeUser{dn: "CN=ally,OU=People,DC=example,DC=lan", sam: "ally", upn: "alice@example.lan", pw: "allypw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	if o := tc.LdapFind("alice", "allypw", true); o.OK {
		t.Errorf("a different account signed in under alice's name: %v", o.Steps)
	}
}

// An account whose user principal name is not name@domain still signs in by its account name (mcc -> mcc@example.lan) when no
// other account has that UPN; when one has, it is the one that signed in and the entry found is refused.
func TestLDAPAccountNameWithDifferentUPN(t *testing.T) {
	f := newFakeLDAP(t, true)
	f.users = append(f.users, &fakeUser{dn: "CN=Michael,OU=People,DC=example,DC=lan", sam: "mcc", upn: "michael.cushard@example.com", pw: "mccpw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	cfg := f.config()
	cfg.LDAPBindDN, cfg.LDAPBindPassword = "", ""
	for _, user := range []string{"mcc", "EXAMPLE\\mcc"} {
		if o := cfg.LdapFind(user, "mccpw", true); !o.OK || o.Failed {
			t.Errorf("%q should sign in: %v", user, o.Steps)
		}
	}
	if o := cfg.LdapFind("mcc", "wrong", true); o.OK {
		t.Errorf("a wrong password signed in: %v", o.Steps)
	}
	// another account owns mcc@example.lan as its UPN: the server signs that one in, not the account named mcc
	f.users = append(f.users, &fakeUser{dn: "CN=Other,OU=People,DC=example,DC=lan", sam: "other", upn: "mcc@example.lan", pw: "otherpw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	if o := cfg.LdapFind("mcc", "otherpw", true); o.OK {
		t.Errorf("a different account signed in under mcc's name: %v", o.Steps)
	}
	if o := cfg.LdapFind("mcc", "mccpw", true); o.OK {
		t.Errorf("mcc's own password cannot sign in while another account owns the UPN: %v", o.Steps)
	}
}

func TestLDAPBindName(t *testing.T) {
	c := LDAPConfig{LDAPBaseDN: "OU=x,DC=example,DC=lan"}
	for in, want := range map[string]string{"alice": "alice@example.lan", "a@b.c": "a@b.c", `EX\a`: `EX\a`} {
		if got := c.ldapBindName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := (LDAPConfig{LDAPBaseDN: "O=x"}).ldapBindName("alice"); got != "alice" {
		t.Errorf("no DC parts: %q", got)
	}
}
