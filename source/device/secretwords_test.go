package device

import (
	"encoding/json"
	"strings"
	"testing"
)

// A representative ArubaOS-CX running configuration (field names as I believe the fullconfigs resource uses them): nothing secret survives the filters, and what is left is still JSON.
func TestConfigFilterHidesSecrets(t *testing.T) {
	src := `{"System":{"hostname":"sw1","mgmt_if":{"ip":"10.1.1.5"}},
 "User":{"admin":{"group":"administrators","password":{"ciphertext":"AQBapSECRET1=","type":"ciphertext"},"authorized_keys":["ssh-rsa AAAAB3NzaC1yc2E user@host"]}},
 "Radius_Server":{"10.1.1.9/default/1812":{"passkey":"AQBapSECRET2=","address":"10.1.1.9"}},
 "TACACS_Server":{"10.1.1.8":{"passkey":"AQBapSECRET3="}},
 "SNMP_Community":{"publicSECRET":{"access_level":"ro"}},
 "SNMPv3_User":{"u1":{"auth_pass":{"ciphertext":"AQBapSECRET4="},"priv_pass":{"ciphertext":"AQBapSECRET5="}}},
 "Certificate":{"c1":{"cert":"-----BEGIN CERTIFICATE-----\nMIIBSECRET6\n-----END CERTIFICATE-----"}},
 "BGP_Router":{"65001":{"neighbors":{"10.2.2.2":{"password":"AQBapSECRET7="}}}},
 "OSPF_Interface":{"vlan10":{"authentication_key":"s3cr3tSECRET8","md5_key":{"1":"SECRET9"}}},
 "Mclag":{"m":{"keepalive_key":"SECRET10"}}}`
	var v any
	if err := json.Unmarshal([]byte(src), &v); err != nil {
		t.Fatal(err)
	}
	ind, _ := json.MarshalIndent(Redact(v), "", " ")
	out := RedactText(string(ind))
	if strings.Contains(strings.ToUpper(out), "SECRET") || strings.Contains(out, "AQBap") || strings.Contains(out, "AAAAB3") {
		t.Errorf("a secret got through:\n%s", out)
	}
	var back any
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Errorf("the answer is no longer JSON: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"hostname": "sw1"`) || !strings.Contains(out, "10.1.1.5") {
		t.Errorf("too much was hidden:\n%s", out)
	}
}

// The words of your own are used by every filter, and taking them away puts the built-in rules back.
func TestSecretWordsOfYourOwn(t *testing.T) {
	t.Cleanup(func() { SetSecretWords(nil) })
	if Redact(map[string]any{"widgetcode": "abc"}).(map[string]any)["widgetcode"] != "abc" {
		t.Fatal("hidden without a word")
	}
	SetSecretWords([]string{"WidgetCode"})
	if Redact(map[string]any{"my_widgetcode": "abc"}).(map[string]any)["my_widgetcode"] != "(hidden)" {
		t.Error("Redact: a key that holds the word")
	}
	if got := RedactText("set widgetcode abc123"); strings.Contains(got, "abc123") {
		t.Errorf("RedactText line: %q", got)
	}
	if got := RedactText(`{"x_widgetcode": "abc123", "y": 1}`); strings.Contains(got, "abc123") {
		t.Errorf("RedactText json: %q", got)
	}
	if err := secretSegment("widgetcodes"); err == nil {
		t.Error("a path with the word was allowed")
	}
	SetSecretWords(nil)
	if err := secretSegment("widgetcodes"); err != nil {
		t.Errorf("after removing the word: %v", err)
	}
}

// RedactConfig keeps a JSON configuration JSON, hides its secrets, and gives the same answer when applied twice.
func TestRedactConfigStaysJSON(t *testing.T) {
	in := `{"System":{"hostname":"sw1","Local_User":{"admin":{"password":"$9$abc","user_group":"admin"}},"SNMP_Community":{"public":{}}},"ntp":"10.0.0.1"}`
	out := RedactConfig(in)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, "$9$abc") || strings.Contains(out, "public") || !strings.Contains(out, "sw1") || !strings.Contains(out, "10.0.0.1") {
		t.Errorf("wrong filtering:\n%s", out)
	}
	if again := RedactConfig(out); again != out {
		t.Errorf("not idempotent:\n%s\n%s", out, again)
	}
	if got := RedactConfig("hostname sw1\nenable secret 5 $1$xx\nsnmp-server community private RO\n"); strings.Contains(got, "$1$xx") || strings.Contains(got, "private") || !strings.Contains(got, "sw1") {
		t.Errorf("text config: %s", got)
	}
}
