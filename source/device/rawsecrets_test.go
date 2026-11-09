package device

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestRunRawLeavesDeviceAnswersAsTheyAre(t *testing.T) {
	cfg := "username admin secret 9 $9$RAWHASH\nsnmp-server community rawcomm RO\n"
	if strings.Contains(RedactConfig(cfg), "RAWHASH") {
		t.Fatal("filtered by default")
	}
	RunRaw(true, func() {
		if got := RedactConfig(cfg); got != cfg {
			t.Errorf("config changed: %q", got)
		}
		if got := RedactText(cfg); got != cfg {
			t.Errorf("text changed: %q", got)
		}
		m := map[string]any{"password": "rawpw", "name": "x"}
		if Redact(m).(map[string]any)["password"] != "rawpw" {
			t.Error("Redact hid a value")
		}
		if RedactConfigValue(cfg) != cfg {
			t.Error("value changed")
		}
		// another goroutine, a driver's own, is not marked: filtered
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if strings.Contains(RedactConfig(cfg), "RAWHASH") {
				t.Error("an unmarked goroutine saw a secret")
			}
		}()
		wg.Wait()
	})
	if strings.Contains(RedactConfig(cfg), "RAWHASH") || Unfiltered() || rawActive.Load() != 0 {
		t.Error("the mark outlived RunRaw")
	}
	RunRaw(false, func() {
		if Unfiltered() {
			t.Error("RunRaw(false) marked")
		}
	})
}

func TestUnimusShowBackupRaw(t *testing.T) {
	st := &uniState{}
	drv, err := Open(uniStub(t, st, nil), Credential{Token: uniTok})
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close(context.Background())
	var out string
	RunRaw(true, func() { out, err = drv.Show(context.Background(), "show backup core1") })
	if err != nil || !strings.Contains(out, "UNIPASS") || !strings.Contains(out, "unicomm") {
		t.Fatalf("raw backup: %v %q", err, out)
	}
}
