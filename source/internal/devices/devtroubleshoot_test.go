package devices

import (
	"strings"
	"testing"

	"netdir/device"
)

func TestShortCommand(t *testing.T) {
	for in, want := range map[string]string{
		"tshoot msmith":    "--troubleshoot-user msmith",
		"tshoot msmith 12": "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot joe@contoso.com 3 --log-level debug": "--troubleshoot-user joe@contoso.com --troubleshoot-hours 3 --log-level debug",
		"--tshoot":                   "--tshoot",
		"tshoot":                     "tshoot",
		"tshoot user msmith":         "--troubleshoot-user msmith",
		"tshoot user msmith 12":      "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot host PC-123":         "--troubleshoot-host PC-123",
		"troubleshoot host PC-123 3": "--troubleshoot-host PC-123 --troubleshoot-hours 3",
		"troubleshoot user msmith":   "--troubleshoot-user msmith",
		"troubleshoot msmith 12":     "--troubleshoot-user msmith --troubleshoot-hours 12",
		"tshoot host":                "--troubleshoot-user host",
		"tshoot user --yes":          "--troubleshoot-user user --yes",
		"troubleshoot":               "troubleshoot",
		"troubleshoot --all-nodes":   "troubleshoot --all-nodes",
		"tshoot --all-nodes":         "tshoot --all-nodes",
		"--tshoot --all-nodes":       "--tshoot --all-nodes",
	} {
		if got := strings.Join(ShortCommand(strings.Fields(in)), " "); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestTroubleshootNames(t *testing.T) {
	for in, want := range map[string]string{"joe.smith@contoso.com": "joe.smith", `CORP\msmith`: "msmith", "msmith": "msmith", "Joe Smith": "", "11111111-2222-3333-4444-555555555555": "", "a'b": ""} {
		if got := TsShortUser(in); got != want {
			t.Errorf("tsShortUser(%q) = %q, want %q", in, got, want)
		}
	}
	devs := []device.Device{{Name: "fw1", Platform: "panos"}, {Name: "fw2", Platform: "panos"}, {Name: "pano", Platform: "panorama"}, {Name: "old", Platform: "panorama", Disabled: true}}
	if d, err := PickLogDevice(devs, ""); err != nil || d.Name != "pano" {
		t.Errorf("the Panorama comes first: %v %v", d.Name, err)
	}
	if d, err := PickLogDevice(devs, "fw2"); err != nil || d.Name != "fw2" {
		t.Errorf("a named firewall: %v %v", d.Name, err)
	}
	if _, err := PickLogDevice(devs[:2], ""); err == nil {
		t.Error("two firewalls and no name: one was picked")
	}
	if _, err := PickLogDevice(nil, ""); err == nil || !strings.Contains(err.Error(), "no enabled panorama or panos") {
		t.Errorf("none: %v", err)
	}
}
