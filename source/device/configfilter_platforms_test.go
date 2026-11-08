package device

import (
	"strings"
	"testing"
)

// Every platform's configuration, in its own format, loses its secrets and keeps its readable parts.
func TestConfigFilterEveryPlatform(t *testing.T) {
	samples := map[string]string{
		"iosxe":   `{"Cisco-IOS-XE-native:native":{"enable":{"secret":{"type":"9","secret":"$9$AAA"}},"username":[{"name":"admin","privilege":15,"secret":{"encryption":"9","secret":"$9$BBB"}}],"snmp-server":{"community":[{"name":"s3cretcomm","RO":[null]}],"host":[{"ip-address":"10.1.1.1","community-or-user":"hostcomm"}]},"tacacs":{"server":[{"name":"t1","key":{"key":"tackey","encryption":"7"}}]},"ntp":{"authentication-key":[{"number":1,"md5":"ntpmd5secret"}]}}}`,
		"nxos":    "username admin password 5 $5$NXPASS role network-admin\nsnmp-server user admin network-admin auth md5 0xAUTHKEY priv 0xPRIVKEY localizedkey\nsnmp-server community nxcomm group network-operator\nsnmp-server host 10.1.1.1 traps version 2c hostcomm2\ntacacs-server key 7 \"TACKEY7\"\nradius-server host 10.2.2.2 key 7 \"RADKEY\" authentication\nfeature bgp\nrouter bgp 65000\n  neighbor 10.3.3.3\n    password 3 BGPPASS\nntp authentication-key 1 md5 NTPKEY 7\nenable secret 5 $5$ENAB\n",
		"eos":     "username admin privilege 15 role network-admin secret sha512 $6$EOSSEC\nusername ops privilege 1 nopassword\nsnmp-server community eoscomm ro\nsnmp-server host 10.1.1.1 version 2c eoshostcomm\nradius-server key 7 RADEOS\ntacacs-server host 10.1.1.2 key 7 TACEOS\nrouter bgp 65000\n   neighbor 10.0.0.1 password 7 EOSBGP\nenable secret sha512 $6$EN\nsnmp-server user u1 g1 v3 auth sha AUTHEOS priv aes PRIVEOS\n",
		"fortios": "config system admin\n    edit \"admin\"\n        set password ENC SH2FORTIPASS\n    next\nend\nconfig system snmp community\n    edit 1\n        set name \"fortcomm\"\n    next\nend\nconfig vpn ipsec phase1-interface\n    edit \"vpn1\"\n        set psksecret ENC FORTIPSK\n    next\nend\nconfig system snmp user\n    edit \"u\"\n        set auth-pwd ENC FAUTH\n        set priv-pwd ENC FPRIV\n    next\nend\nconfig user ldap\n    edit \"l\"\n        set password ENC LDAPPW\n    next\nend\nconfig system api-user\n    edit \"api\"\n        set api-key ENC APIK\n    next\nend\nconfig router bgp\n    config neighbor\n        edit \"10.0.0.1\"\n            set password ENC BGPFORT\n        next\n    end\nend\nconfig vpn certificate local\n    edit \"c\"\n        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFAKEKEYDATA\n-----END ENCRYPTED PRIVATE KEY-----\"\n    next\nend\nconfig system fortiguard\n    set auth-token ENC FTOK\nend\n",
		"panos":   "<config><mgt-config><users><entry name=\"admin\"><phash>$5$PANHASH</phash></entry></users></mgt-config><deviceconfig><system><snmp-setting><access-setting><version><v2c><snmp-community-string>pancomm</snmp-community-string></v2c></version></access-setting></snmp-setting></system></deviceconfig><shared><authentication-profile><entry name=\"a\"><method><ldap><server-profile>x</server-profile></ldap></method></entry></authentication-profile><server-profile><radius><entry name=\"r\"><server><entry name=\"s\"><secret>PANRADSEC</secret></entry></server></entry></radius></server-profile></shared><network><ike><gateway><entry name=\"g\"><authentication><pre-shared-key><key>PANPSK</key></pre-shared-key></authentication></entry></gateway></ike></network></config>",
		"junos":   "system {\n    root-authentication {\n        encrypted-password \"$6$JUNROOT\"; ## SECRET-DATA\n    }\n    login {\n        user ops {\n            authentication {\n                encrypted-password \"$6$JUNOPS\";\n                ssh-rsa \"ssh-rsa AAAAB3JUNKEY ops@x\";\n            }\n        }\n    }\n    radius-server 10.1.1.1 {\n        secret \"$9$JUNRAD\";\n    }\n}\nsnmp {\n    community juncomm {\n        authorization read-only;\n    }\n}\nprotocols {\n    bgp {\n        group g {\n            authentication-key \"$9$JUNBGP\";\n        }\n    }\n}\nsecurity {\n    ike {\n        policy p {\n            pre-shared-key ascii-text \"$9$JUNPSK\";\n        }\n    }\n}\n",
	}
	secrets := map[string][]string{
		"iosxe":   {"$9$AAA", "$9$BBB", "s3cretcomm", "hostcomm", "tackey", "ntpmd5secret"},
		"nxos":    {"NXPASS", "AUTHKEY", "PRIVKEY", "nxcomm", "hostcomm2", "TACKEY7", "RADKEY", "BGPPASS", "NTPKEY", "ENAB"},
		"eos":     {"EOSSEC", "eoscomm", "eoshostcomm", "RADEOS", "TACEOS", "EOSBGP", "AUTHEOS", "PRIVEOS"},
		"fortios": {"FORTIPASS", "fortcomm", "FORTIPSK", "FAUTH", "FPRIV", "LDAPPW", "APIK", "BGPFORT", "MIIFAKEKEYDATA", "FTOK"},
		"panos":   {"PANHASH", "pancomm", "PANRADSEC", "PANPSK"},
		"junos":   {"JUNROOT", "JUNOPS", "JUNRAD", "juncomm", "JUNBGP", "JUNPSK"},
	}
	readable := map[string]string{"iosxe": "10.1.1.1", "nxos": "feature bgp", "eos": "router bgp 65000", "fortios": "config system admin", "panos": "<deviceconfig>", "junos": "protocols"}
	for k, v := range samples {
		out := RedactConfig(v)
		for _, sec := range secrets[k] {
			if strings.Contains(out, sec) {
				t.Errorf("%s: %q is still in the answer:\n%s", k, sec, out)
			}
		}
		if !strings.Contains(out, readable[k]) {
			t.Errorf("%s: %q was hidden too:\n%s", k, readable[k], out)
		}
		if again := RedactConfig(out); again != out {
			t.Errorf("%s: not idempotent", k)
		}
	}
}
