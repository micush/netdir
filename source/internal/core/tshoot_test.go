package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTshootRedactsSecrets(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"groups":[{"key":"dgw","priority":100,"neighbors":[]}],"bgp":{"neighbors":[{"peer":"192.0.2.1","password":"hunter2","multihop":0}]},
		"web":{"key_file":"/x/key.pem","listen":"127.0.0.1:1"},"cluster":{"join_code":"netdir-join-v1:abc","token":"zzz","code":""},"rcode":"NOERROR"}`), &v)
	out, n := RedactJSON(v)
	raw, _ := json.Marshal(out)
	s := string(raw)
	for _, leak := range []string{"dgw\"", "hunter2", "netdir-join-v1:abc", "zzz", "/x/key.pem"} {
		if leak == "dgw\"" {
			if strings.Contains(s, `"key":"dgw"`) {
				t.Errorf("the gateway key leaked: %s", s)
			}
			continue
		}
		if strings.Contains(s, leak) {
			t.Errorf("%q leaked: %s", leak, s)
		}
	}
	for _, keep := range []string{"192.0.2.1", "NOERROR", "127.0.0.1:1", `"priority":100`} {
		if !strings.Contains(s, keep) {
			t.Errorf("%q must stay: %s", keep, s)
		}
	}
	if n < 5 {
		t.Errorf("counted %d removals", n)
	}
}

func TestTshootRedactsText(t *testing.T) {
	in := "router bgp 65001\n neighbor 192.0.2.1 password hunter2\n neighbor 192.0.2.2 password 7 0822455D0A16\n ip prefix-list x\nsnmp community public\n"
	out, n := RedactText(in)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "0822455D0A16") || n < 2 {
		t.Fatalf("secrets left (%d): %s", n, out)
	}
	if !strings.Contains(out, "router bgp 65001") || !strings.Contains(out, "ip prefix-list x") {
		t.Fatalf("too much removed: %s", out)
	}
}
