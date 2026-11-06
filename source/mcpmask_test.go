package main

import (
	"encoding/json"
	"strings"
	"testing"

	"netdir/device"
)

func TestMaskText(t *testing.T) {
	in := "peer 8.8.8.8:443 via 10.1.1.1 gw 192.168.0.1 lo 127.0.0.1 doc 203.0.113.9 cgnat 100.64.1.1 mask 255.255.255.0 wild 0.0.0.255 " +
		"v6 2606:4700:4700::1111/64 ula fd00::1 ll fe80::1 doc6 2001:db8::5 mac aa:bb:cc:00:00:01 time 12:30:45 " +
		"AS15169 AS65001 AS 3356 router bgp 64512 neighbor 1.1.1.1 remote-as 13335 contact admin@example.com"
	out := maskText(in)
	for _, leak := range []string{"8.8.8.8", "2606:4700", "AS15169", "AS 3356", "13335", "1.1.1.1", "admin@example.com"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	for _, keep := range []string{":443", "10.1.1.1", "192.168.0.1", "127.0.0.1", "203.0.113.9", "100.64.1.1", "255.255.255.0", "0.0.0.255", "fd00::1", "fe80::1", "2001:db8::5",
		"aa:bb:cc:00:00:01", "12:30:45", "AS65001", "router bgp 64512", "/64"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was hidden: %s", keep, out)
		}
	}
	if maskText("8.8.8.8 8.8.8.8 8.8.4.4") == "" || strings.Count(maskText("8.8.8.8 and 8.8.8.8"), "PUBLIC-IP-") != 2 {
		t.Error("tokens")
	}
	a := strings.Fields(maskText("8.8.8.8 8.8.8.8 8.8.4.4"))
	if a[0] != a[1] || a[0] == a[2] {
		t.Errorf("same value, same token; different value, different token: %v", a)
	}
}

func TestMaskJSON(t *testing.T) {
	in := `{"remote-as":15169,"local_as":"65001","asn":4200000001,"serial":"FOC1234X0AB","as-path":"65001 3356 15169","big":9007199254740993,
		"addresses":["203.0.114.7/24","10.0.0.1/24"],"8.8.4.4":{"ok":1},"snmp_contact":"noc@corp.example","n":5}`
	out := string(mcpMaskJSON([]byte(in)))
	for _, leak := range []string{"15169", "FOC1234X0AB", "FOC1234", "3356", "203.0.114.7", "8.8.4.4", "noc@corp.example"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	for _, keep := range []string{`"local_as":"65001"`, "4200000001", "65001 PUBLIC-AS-", "10.0.0.1/24", "9007199254740993", `"n":5`, `"serial":"****X0AB"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was hidden or changed: %s", keep, out)
		}
	}
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) != nil {
		t.Errorf("not JSON: %s", out)
	}
}

func TestMaskUnmask(t *testing.T) {
	tok := maskTag("PUBLIC-IP", "8.8.8.8")
	body := map[string]any{"vip4": tok + "/24", "l": []any{tok, "10.0.0.1"}, "n": 5.0}
	mcpUnmask(body)
	if body["vip4"] != mcpHidden || body["l"].([]any)[0] != mcpHidden || body["l"].([]any)[1] != "10.0.0.1" || body["n"] != 5.0 {
		t.Errorf("%v", body)
	}
}

// Through the real tool path: a device on a public address is listed by a token, and an error text is scrubbed too.
func TestMCPMasksPublicAddresses(t *testing.T) {
	post := devEnv(t, "127.0.0.1 rw")
	_, m := post(mcpCall("list_devices", `{}`))
	base, _ := toolResult(t, m)
	if strings.Contains(base, "PUBLIC-IP") {
		t.Fatalf("a loopback device was masked: %s", base)
	}
	e, post2 := mcpEnv(t, "127.0.0.1 rw")
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "u", Password: "p"}}
	sup.dc.Settings.Devices = []device.Device{{Name: "edge", Platform: "iosxe", Address: "8.8.8.8", Credential: "lab", Insecure: true}}
	sup.mu.Unlock()
	_, m = post2(mcpCall("list_devices", `{}`))
	txt, _ := toolResult(t, m)
	if strings.Contains(txt, "8.8.8.8") || !strings.Contains(txt, "PUBLIC-IP-") {
		t.Errorf("list_devices: %s", txt)
	}
	_, m = post2(mcpCall("get_config", `{}`))
	if txt, _ = toolResult(t, m); strings.Contains(txt, "8.8.8.8") {
		t.Errorf("get_config: %s", txt)
	}
}
