package device

import (
	"context"
	"strings"
	"testing"
)

func TestObserviumImportRows(t *testing.T) {
	rows := []map[string]any{
		{"device_id": "1", "hostname": "core-sw.example.com", "sysName": "core-sw", "os": "ios", "location": "DC 1, Row 2"},
		{"device_id": "2", "hostname": "10.0.0.9", "sysName": "fw 9", "os": "fortigate"},
		{"device_id": "3", "hostname": "web1.example.com", "os": "linux"},
		{"device_id": "4", "hostname": "dup.example.com", "sysName": "core-sw", "os": "nxos"},
		{"device_id": "5", "hostname": "already.example.com", "sysName": "x", "os": "eos"},
		{"device_id": "6", "hostname": "bad host!", "ip": "10.0.0.6", "sysName": "viaip", "os": "junos"},
		{"device_id": "7", "hostname": "bad host!", "os": "junos"},
	}
	got, skipped, err := obsImportRows(rows, []Device{{Name: "other", Address: "already.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range got {
		names = append(names, d.Name+":"+d.Platform+":"+d.Address)
		if !d.Disabled || d.Credential != "" || len(d.Options) != 0 {
			t.Errorf("%s: disabled=%v credential=%q", d.Name, d.Disabled, d.Credential)
		}
		if d.Tags[0] != "source=observium" {
			t.Errorf("%s tags %v", d.Name, d.Tags)
		}
	}
	want := "core-sw:iosxe:core-sw.example.com fw-9:fortios:10.0.0.9 core-sw-2:nxos:dup.example.com viaip:junos:10.0.0.6"
	if strings.Join(names, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(names, " "), want)
	}
	if got[0].Tags[1] != "site=DC_1_Row_2" {
		t.Errorf("location tag %v", got[0].Tags)
	}
	why := map[string]string{}
	for _, s := range skipped {
		why[s.Name] = s.Reason
	}
	if len(skipped) != 3 || !strings.Contains(why["web1.example.com"], "no driver") || !strings.Contains(why["already.example.com"], "already") || !strings.Contains(why["bad host!"], "no address") {
		t.Errorf("skipped %+v", skipped)
	}
	// what was made is valid as it is, with no login
	if err := Validate(got, nil); err != nil {
		t.Errorf("validate: %v", err)
	}
	got[0].Disabled = false
	if err := Validate(got, nil); err == nil || !strings.Contains(err.Error(), "login before enabling") {
		t.Errorf("enabled with no login: %v", err)
	}
}

func TestObserviumImportFromTheServer(t *testing.T) {
	d, _ := obsStub(t, "")
	got, skipped, err := ObserviumImport(context.Background(), d, Credential{Name: "c", Token: "APITOKEN"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "core-sw" || got[0].Platform != "iosxe" || len(skipped) != 2 {
		t.Errorf("%+v %+v", got, skipped)
	}
	d.Options = map[string]string{"device": "ipam2"}
	if _, _, err := ObserviumImport(context.Background(), d, Credential{Name: "c", Token: "APITOKEN"}, nil); err == nil {
		t.Error("a single monitored device was imported from")
	}
}
