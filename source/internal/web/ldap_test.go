package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"netdir/internal/core"
)

func TestLDAPConfigRules(t *testing.T) {
	c := core.LDAPConfig{LDAPServers: []string{"ldaps://dc1.example.lan, ldap://dc2.example.lan:389/"}, LDAPBindDN: " CN=svc,DC=x ", LDAPBindPassword: "p"}
	if err := c.ValidateLDAP(); err != nil || strings.Join(c.LDAPServers, "|") != "ldaps://dc1.example.lan|ldap://dc2.example.lan:389" || c.LDAPBindDN != "CN=svc,DC=x" {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range []core.LDAPConfig{
		{LDAPServers: []string{"http://dc1"}}, {LDAPServers: []string{"dc1.example.lan"}}, {LDAPServers: []string{"ldaps://u:p@dc1"}},
		{LDAPServers: []string{"ldaps://dc1/base"}}, {LDAPBaseDN: "DC=x\nDC=y"}, {LDAPRWGroup: strings.Repeat("x", 600)},
		{LDAPServers: strings.Fields("ldap://a ldap://b ldap://c ldap://d ldap://e ldap://f ldap://g ldap://h ldap://i")},
	} {
		if err := bad.ValidateLDAP(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	// half set up is not an error and is not enabled
	h := core.LDAPConfig{LDAPServers: []string{"ldaps://dc1"}, LDAPBindDN: "x"}
	if err := h.ValidateLDAP(); err != nil || h.Enabled() {
		t.Fatalf("half set up: %v", err)
	}
	// shared by the cluster only when set; read-only accounts are not shown the password
	dc := core.NewDaemonConfig()
	if core.SharedOf(dc).LDAP != nil {
		t.Fatal("an empty LDAP block appears in the shared document")
	}
	dc.Web.LDAPConfig = core.LDAPConfig{LDAPServers: []string{"ldaps://dc1"}, LDAPBindDN: "svc", LDAPBindPassword: "hunter2", LDAPBaseDN: "DC=x", LDAPRWGroup: "g"}
	sc := core.SharedOf(dc)
	if sc.LDAP == nil || sc.LDAP.LDAPBindDN != "svc" {
		t.Fatal("not shared")
	}
	b, _ := json.Marshal(dc)
	var back core.DaemonConfig
	if err := json.Unmarshal(b, &back); err != nil || back.Web.LDAPBindPassword != "hunter2" || !back.Web.LDAPConfig.Enabled() {
		t.Fatalf("round trip: %v %+v", err, back.Web.LDAPConfig)
	}
	red, _ := json.Marshal(redactSecrets(dc.Web))
	if strings.Contains(string(red), "hunter2") {
		t.Fatalf("the bind password is shown: %s", red)
	}
	_ = fmt.Sprint
}
