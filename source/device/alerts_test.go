package device

import (
	"context"
	"strings"
	"testing"
)

// What each platform that reports alerts counts as one (the stubs of the drivers' own tests hold the data).
func TestActiveAlertsOfTheManagementPlatforms(t *testing.T) {
	ctx := context.Background()
	alerts := func(t *testing.T, drv Driver) string {
		t.Helper()
		ar, ok := drv.(AlertReporter)
		if !ok {
			t.Fatalf("%T does not report alerts", drv)
		}
		a, err := ar.ActiveAlerts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(a, "|")
	}
	t.Run("afc", func(t *testing.T) {
		d := afcStub(t, &afcState{})
		if got := alerts(t, openAFC(t, d, "S3CRET")); got != "switch leaf2 unreachable" { // acknowledged and cleared ones are not alerts
			t.Errorf("afc: %q", got)
		}
	})
	t.Run("aviatrix", func(t *testing.T) {
		d := avxStub(t, &avxState{})
		if got := alerts(t, open(t, d, Credential{Username: "admin", Password: "pw"})); got != "spoke1: instance stopped" {
			t.Errorf("aviatrix: %q", got)
		}
	})
	t.Run("copilot", func(t *testing.T) {
		d, c := avcStub(t, "k3y", nil)
		drv, err := Open(d, c)
		if err != nil {
			t.Fatal(err)
		}
		want := "gateway spoke-gw-1 down|gateway spoke-gw-2 degraded|tunnel s2c-branch-office down|BGP transit-gw-1 peer(10.0.0.1) not established"
		if got := alerts(t, drv); got != want {
			t.Errorf("copilot: %q", got)
		}
	})
	t.Run("panorama", func(t *testing.T) {
		ans := panPanoramaAnswers()
		d, _ := panStub(t, ans)
		d.Platform = "panorama"
		if got := alerts(t, open(t, d, panCred)); got != "" {
			t.Errorf("panorama with every firewall connected: %q", got)
		}
		k := "<show><devices><all></all></devices></show>"
		ans[k] = strings.Replace(ans[k], "<connected>yes</connected>", "<connected>no</connected>", 1)
		d, _ = panStub(t, ans)
		d.Platform = "panorama"
		if got := alerts(t, open(t, d, panCred)); got != "firewall fw1 is not connected" {
			t.Errorf("panorama: %q", got)
		}
	})
	t.Run("meraki", func(t *testing.T) {
		d := merakiStub(t, newMerakiState())
		if got := alerts(t, openMeraki(t, d, "KEY")); got != "Q2DD-EEEE-FFFF offline" {
			t.Errorf("meraki: %q", got)
		}
	})
	t.Run("unimus", func(t *testing.T) {
		d := uniStub(t, &uniState{}, nil)
		if got := alerts(t, open(t, d, Credential{Token: uniTok})); got != "10.0.0.7 backup failed" {
			t.Errorf("unimus: %q", got)
		}
	})
	t.Run("proxmox", func(t *testing.T) {
		d := pveStub(t, &pveState{secret: "SEC"})
		if got := alerts(t, openPVE(t, d, Credential{Name: "a", Token: "root@pam!nd=SEC"})); got != "node pve2 offline|storage nfs1 unknown" {
			t.Errorf("proxmox: %q", got)
		}
	})
	t.Run("vcenter", func(t *testing.T) {
		d := vcStub(t, &vcState{})
		if got := alerts(t, open(t, d, vcCred)); got != "host esx2.example.com disconnected|appliance load orange" {
			t.Errorf("vcenter: %q", got)
		}
	})
	t.Run("pbs", func(t *testing.T) {
		drv := openPx(t, "pbs", &pxState{prefix: "PBSAPIToken", secret: "SEC"}, Credential{Name: "a", Token: "root@pam!nd:SEC"})
		// a full datastore and the failed task of the last day: not the one with warnings, the old one or the one that worked
		if got := alerts(t, drv); got != "datastore backup2 100% full|task garbage_collection backup1 failed" {
			t.Errorf("pbs: %q", got)
		}
	})
	t.Run("pdm", func(t *testing.T) {
		drv := openPx(t, "pdm", &pxState{prefix: "PDMAPIToken", secret: "SEC"}, Credential{Name: "a", Token: "root@pam!nd:SEC"})
		if got := alerts(t, drv); got != "remote bk unreachable|pve_node offline" {
			t.Errorf("pdm: %q", got)
		}
	})
}
