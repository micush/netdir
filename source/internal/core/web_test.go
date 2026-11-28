package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWebConfigValidation(t *testing.T) {
	ok := DefaultWeb()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Listen != ":22161" || ok.Group != "netdir,netdir-users" || ok.PAMService != "netdir" || ok.MaxFailedLogins != 3 || ok.FailedLoginWindowMinutes != 1 || ok.LockoutMinutes != 15 {
		t.Fatalf("defaults wrong: %+v", ok)
	}
	for name, mod := range map[string]func(*WebConfig){
		"bad listen":   func(w *WebConfig) { w.Listen = "22161" },
		"bad port":     func(w *WebConfig) { w.Listen = ":99999" },
		"cert w/o key": func(w *WebConfig) { w.CertFile = "/x.crt" },
		"empty group":  func(w *WebConfig) { w.Group = "" },
		"zero idle":    func(w *WebConfig) { w.SessionIdleMinutes = 0 },
		"zero tries":   func(w *WebConfig) { w.MaxFailedLogins = 0 },
		"zero window":  func(w *WebConfig) { w.FailedLoginWindowMinutes = 0 },
		"zero lockout": func(w *WebConfig) { w.LockoutMinutes = 0 },
	} {
		w := DefaultWeb()
		mod(&w)
		if w.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// the old "enabled" key still loads (the GUI is always on) and is dropped
	var legacy WebConfig
	if err := json.Unmarshal([]byte(`{"enabled": false, "listen": ":1234"}`), &legacy); err != nil {
		t.Fatalf("old config with web.enabled must still load: %v", err)
	}
	if legacy.Listen != ":1234" || legacy.LegacyEnabled != nil {
		t.Fatalf("legacy load: %+v", legacy)
	}
	if b, _ := json.Marshal(legacy); strings.Contains(string(b), `"enabled"`) {
		t.Fatalf("enabled must not be written back: %s", b)
	}
}
