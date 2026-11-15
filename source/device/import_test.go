package device

import (
	"context"
	"errors"
	"fmt"
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
		{"device_id": "8", "hostname": "aptxipm02-m.net.axway.int", "sysName": "aptxipm02-m.net.axway.int", "os": "infoblox"},
		{"device_id": "9", "hostname": "aptxipm02-new.net.axway.int", "os": "infoblox"},
		{"device_id": "10", "hostname": "lphxpve12.net.axway.int", "os": "pve"},
	}
	got, skipped := impBuild("observium", obsImportRows(rows), []Device{{Name: "other", Address: "already.example.com"}})
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
	want := "core-sw:ios:core-sw.example.com fw-9:fortios:10.0.0.9 viaip:junos:10.0.0.6 aptxipm02:nios:aptxipm02-m.net.axway.int lphxpve12:proxmox:lphxpve12.net.axway.int"
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
	if len(skipped) != 5 || !strings.Contains(why["dup.example.com"], "same name") || !strings.Contains(why["aptxipm02-new.net.axway.int"], "same name") || !strings.Contains(why["web1.example.com"], "no driver") || !strings.Contains(why["already.example.com"], "already") || !strings.Contains(why["bad host!"], "no address") {
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
	got, skipped, err := ImportDevices(context.Background(), d, Credential{Name: "c", Token: "APITOKEN"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "core-sw" || got[0].Platform != "ios" || len(skipped) != 2 {
		t.Errorf("%+v %+v", got, skipped)
	}
	d.Options = map[string]string{"device": "ipam2"}
	if _, _, err := ImportDevices(context.Background(), d, Credential{Name: "c", Token: "APITOKEN"}, nil); err == nil {
		t.Error("a single monitored device was imported from")
	}
}

func TestImportPlatformGuesses(t *testing.T) {
	for in, want := range map[[3]string]string{
		{"cisco", "ios-xe", "cat9k"}: "iosxe", {"cisco", "nx-os", "n9k"}: "nxos", {"juniper", "junos", "mx"}: "junos",
		{"fortinet", "fortigate", ""}: "fortios", {"paloalto", "pan-os", ""}: "panos", {"arista", "eos", ""}: "eos",
		{"f5", "big-ip", ""}: "bigip", {"hpe", "aos-cx", "8325"}: "aoscx", {"vmware", "esxi", ""}: "", {"cisco", "wlc", "9800"}: "",
	} {
		if got := ipfPlatform(in[0], in[1], in[2]); got != want {
			t.Errorf("ipfabric %v: %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"Net-Cisco-Standard-SNMP": "iosxe", "Net-Cisco-Nexus-SNMP": "nxos", "Net-Fortinet-Fortigate-SNMP": "fortios",
		"OS-Linux-SNMP": "", "": "", "Net-Paloalto-Standard-SNMP": "panos", "Net-Arista-Standard-SNMP": "eos",
	} {
		if got := centPlatform(in); got != want {
			t.Errorf("centreon %q: %q, want %q", in, got, want)
		}
	}
}

func TestImportFromIPFabricAndCentreon(t *testing.T) {
	d := ipfStub(t, &ipfState{})
	got, skipped, err := ImportDevices(context.Background(), d, Credential{Name: "c", Token: "TOK"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got)+len(skipped) == 0 {
		t.Fatal("IP Fabric: nothing read")
	}
	for _, x := range got {
		if !x.Disabled || x.Credential != "" || x.Tags[0] != "source=ipfabric" || x.Platform != "iosxe" {
			t.Errorf("ipfabric %+v", x)
		}
	}
	cd := centStub(t, &centState{}, "/centreon", "latest")
	got, skipped, err = ImportDevices(context.Background(), cd, Credential{Name: "c", Token: "APITOKEN"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got)+len(skipped) != 3 {
		t.Errorf("centreon: %d imported, %d skipped, want 3 hosts in all", len(got), len(skipped))
	}
	for _, s := range skipped {
		if !strings.Contains(s.Reason, "no driver") {
			t.Errorf("centreon skip %+v", s)
		}
	}
	if _, _, err := ImportDevices(context.Background(), Device{Name: "x", Platform: "iosxe"}, Credential{}, nil); err == nil {
		t.Error("a switch was imported from")
	}
}

func TestImportFromPanorama(t *testing.T) {
	d, _ := panStub(t, panPanoramaAnswers())
	d.Platform = "panorama"
	got, skipped, err := ImportDevices(context.Background(), d, panCred, nil)
	if err != nil || len(skipped) != 0 || len(got) != 1 {
		t.Fatalf("%v %+v %+v", err, got, skipped)
	}
	x := got[0]
	if x.Name != "fw1" || x.Platform != "panos" || x.Address != "10.0.0.5" || !x.Disabled || x.Credential != "" || strings.Join(x.Tags, " ") != "source=panorama dg=dg1" {
		t.Errorf("%+v", x)
	}
	// it is already there the second time
	got, skipped, _ = ImportDevices(context.Background(), d, panCred, []Device{{Name: "fw1", Address: "10.0.0.5"}})
	if len(got) != 0 || len(skipped) != 1 {
		t.Errorf("%+v %+v", got, skipped)
	}
}

func TestImportFromPDMAndAFC(t *testing.T) {
	rows := pdmImportRows([]map[string]any{
		{"id": "prod", "type": "pve", "nodes": []any{map[string]any{"hostname": "lphxpve12.net.axway.int"}, map[string]any{"hostname": "10.0.0.13"}}},
		{"id": "bk", "type": "pbs", "nodes": []any{map[string]any{"hostname": "pbs1.example.com"}}},
		{"id": "odd", "type": "other", "nodes": []any{map[string]any{"hostname": "x.example.com"}}},
	})
	got, skipped := impBuild("pdm", rows, nil)
	var s []string
	for _, d := range got {
		s = append(s, d.Name+":"+d.Platform+":"+d.Address+":"+strings.Join(d.Tags, ","))
	}
	want := "lphxpve12:proxmox:lphxpve12.net.axway.int:source=pdm,remote=prod prod-2:proxmox:10.0.0.13:source=pdm,remote=prod pbs1:pbs:pbs1.example.com:source=pdm,remote=bk"
	if strings.Join(s, " ") != want || len(skipped) != 1 {
		t.Errorf("pdm: %s\n%+v", strings.Join(s, " "), skipped)
	}
	got, skipped = impBuild("afc", afcImportRows([]map[string]any{
		{"uuid": "s1", "name": "leaf1", "ip_address": "10.1.1.1", "fabric_name": "dc 1"}, {"uuid": "s2", "name": "leaf2"},
	}), nil)
	if len(got) != 2 || len(skipped) != 0 || got[0].Platform != "aoscx" || got[0].Address != "10.1.1.1" || got[0].Tags[1] != "fabric=dc_1" || got[1].Address != "leaf2" {
		t.Errorf("afc: %+v %+v", got, skipped)
	}
	// from the AFC stub
	d := afcStub(t, &afcState{})
	got, _, err := ImportDevices(context.Background(), d, Credential{Name: "c", Username: "admin", Password: "S3CRET"}, nil)
	if err != nil || len(got) != 2 || got[0].Name != "leaf1" {
		t.Errorf("afc stub: %v %+v", err, got)
	}
}

func TestProxmoxGuestImport(t *testing.T) {
	answers := map[string]any{
		"/nodes/pve1/qemu/100/config": map[string]any{"ostype": "l26"},
		"/nodes/pve1/qemu/100/agent/network-get-interfaces": map[string]any{"result": []any{
			map[string]any{"name": "lo", "ip-addresses": []any{map[string]any{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}}},
			map[string]any{"name": "docker0", "ip-addresses": []any{map[string]any{"ip-address": "172.17.0.1", "ip-address-type": "ipv4"}}},
			map[string]any{"name": "eth0", "ip-addresses": []any{map[string]any{"ip-address": "fe80::1", "ip-address-type": "ipv6"}, map[string]any{"ip-address": "10.0.0.50", "ip-address-type": "ipv4"}}},
		}},
		"/nodes/pve1/qemu/101/config":                       map[string]any{"ostype": "win11"},
		"/nodes/pve1/qemu/105/config":                       map[string]any{"ostype": "other"},
		"/nodes/pve1/qemu/102/config":                       map[string]any{"ostype": "l26", "ipconfig0": "ip=10.0.0.52/24,gw=10.0.0.1"},
		"/nodes/pve2/lxc/200/config":                        map[string]any{"ostype": "debian"},
		"/nodes/pve2/lxc/200/interfaces":                    []any{map[string]any{"name": "lo", "inet": "127.0.0.1/8"}, map[string]any{"name": "eth0", "inet": "10.0.0.60/24"}},
		"/nodes/pve2/lxc/201/config":                        map[string]any{"ostype": "unmanaged"},
		"/nodes/pve2/lxc/202/config":                        map[string]any{"ostype": "alpine", "net0": "name=eth0,bridge=vmbr0,ip=dhcp"},
		"/nodes/pve2/lxc/203/config":                        map[string]any{"ostype": "ubuntu", "net0": "name=eth0,bridge=vmbr0,ip=10.0.0.63/24,gw=10.0.0.1"},
		"/nodes/pve1/qemu/104/config":                       map[string]any{"ostype": "l26"},
		"/nodes/pve1/qemu/104/agent/network-get-interfaces": nil, // the agent is not running: an error
	}
	get := func(_ context.Context, p string) (any, error) {
		if v, ok := answers[p]; ok && v != nil {
			return v, nil
		}
		return nil, errors.New("not found: " + p)
	}
	guests := []map[string]any{
		{"vmid": float64(203), "node": "pve2", "type": "lxc", "name": "ct-static", "status": "running"},
		{"vmid": float64(100), "node": "pve1", "type": "qemu", "name": "web1", "status": "running"},
		{"vmid": float64(101), "node": "pve1", "type": "qemu", "name": "winbox", "status": "running"},
		{"vmid": float64(102), "node": "pve1", "type": "qemu", "name": "ci-vm", "status": "running"},
		{"vmid": float64(103), "node": "pve1", "type": "qemu", "name": "tmpl", "status": "stopped", "template": float64(1)},
		{"vmid": float64(104), "node": "pve1", "type": "qemu", "name": "noagent", "status": "running"},
		{"vmid": float64(200), "node": "pve2", "type": "lxc", "name": "ct1", "status": "running"},
		{"vmid": float64(201), "node": "pve2", "type": "lxc", "name": "appliance", "status": "running"},
		{"vmid": float64(202), "node": "pve2", "type": "lxc", "name": "dhcp-ct", "status": "running"},
		{"vmid": float64(105), "node": "pve1", "type": "qemu", "name": "bsd", "status": "running"},
		{"vmid": float64(106), "node": "pve1", "type": "qemu", "name": "off-vm", "status": "stopped"},
		{"vmid": float64(107), "node": "pve2", "type": "lxc", "name": "off-ct", "status": "stopped"},
		{"vmid": float64(300), "node": "pve2", "type": "storage", "name": "local"},
	}
	got, skipped := impBuild("proxmox", pveImportRows(context.Background(), guests, get), []Device{{Name: "x", Address: "10.0.0.63"}})
	var s []string
	for _, d := range got {
		if want := map[string]string{"winbox": "windows"}[d.Name]; (want == "" && d.Platform != "linux") || (want != "" && d.Platform != want) || !d.Disabled || d.Credential != "" {
			t.Errorf("%+v", d)
		}
		s = append(s, d.Name+"@"+d.Address+" "+strings.Join(d.Tags, ","))
	}
	want := []string{
		"web1@10.0.0.50 source=proxmox,node=pve1,vmid=100,type=qemu",
		"winbox@winbox source=proxmox,node=pve1,vmid=101,type=qemu,address=name",
		"ci-vm@10.0.0.52 source=proxmox,node=pve1,vmid=102,type=qemu",
		"noagent@noagent source=proxmox,node=pve1,vmid=104,type=qemu,address=name",
		"ct1@10.0.0.60 source=proxmox,node=pve2,vmid=200,type=lxc",
		"dhcp-ct@dhcp-ct source=proxmox,node=pve2,vmid=202,type=lxc,address=name",
	}
	if strings.Join(s, "\n") != strings.Join(want, "\n") {
		t.Errorf("devices:\n%s", strings.Join(s, "\n"))
	}
	why := map[string]string{}
	for _, k := range skipped {
		why[k.Name] = k.Reason
	}
	if !strings.Contains(fmt.Sprint(skipped), "ct-static") {
		t.Errorf("the skipped list does not name the container: %+v", skipped)
	}
	for name, frag := range map[string]string{"off-vm": "not running", "off-ct": "not running", "bsd": "other", "tmpl": "template", "appliance": "unmanaged", "10.0.0.63": "same address", "local": "not a VM"} {
		if !strings.Contains(why[name], frag) {
			t.Errorf("%s: %q (want %q); skipped %+v", name, why[name], frag, skipped)
		}
	}
}

func TestVCenterVMImport(t *testing.T) {
	answers := map[string]any{
		"/vcenter/vm/vm-10/guest/identity":              map[string]any{"family": "LINUX", "host_name": "web1.example.com", "ip_address": "10.1.0.10"},
		"/vcenter/vm/vm-11/guest/identity":              map[string]any{"family": "WINDOWS", "host_name": "dc1", "ip_address": "fe80::1"},
		"/vcenter/vm/vm-11/guest/networking/interfaces": []any{map[string]any{"nic": "4000", "ip": map[string]any{"ip_addresses": []any{map[string]any{"ip_address": "fe80::1"}, map[string]any{"ip_address": "10.1.0.11"}}}}},
		"/vcenter/vm/vm-12":                             map[string]any{"guest_OS": "UBUNTU_64"},
		"/vcenter/vm/vm-13":                             map[string]any{"guest_OS": "WINDOWS_9_SERVER_64"},
		"/vcenter/vm/vm-14/guest/identity":              map[string]any{"family": "DARWIN"},
		"/vcenter/vm/vm-15":                             map[string]any{"guest_OS": "OTHER_64"},
		"/vcenter/vm/vm-16/guest/identity":              map[string]any{"family": "LINUX", "host_name": "appl.example.com"},
	}
	get := func(_ context.Context, p string) (any, error) {
		if v, ok := answers[p]; ok {
			return v, nil
		}
		return nil, errors.New("not found: " + p)
	}
	vms := []map[string]any{
		{"vm": "vm-10", "name": "web1", "power_state": "POWERED_ON"},
		{"vm": "vm-11", "name": "dc1", "power_state": "POWERED_ON"},
		{"vm": "vm-12", "name": "no-tools-linux", "power_state": "POWERED_ON"},
		{"vm": "vm-13", "name": "no-tools-win", "power_state": "POWERED_ON"},
		{"vm": "vm-14", "name": "mac", "power_state": "POWERED_ON"},
		{"vm": "vm-15", "name": "mystery", "power_state": "POWERED_ON"},
		{"vm": "vm-16", "name": "appl", "power_state": "POWERED_ON"},
		{"vm": "vm-17", "name": "off", "power_state": "POWERED_OFF"},
	}
	got, skipped := impBuild("vcenter", vcImportRows(context.Background(), vms, get), nil)
	var s []string
	for _, d := range got {
		if !d.Disabled || d.Credential != "" {
			t.Errorf("%+v", d)
		}
		s = append(s, d.Name+":"+d.Platform+"@"+d.Address+" "+strings.Join(d.Tags, ","))
	}
	want := []string{
		"web1:linux@10.1.0.10 source=vcenter,vm=vm-10",
		"dc1:windows@10.1.0.11 source=vcenter,vm=vm-11",
		"no-tools-linux:linux@no-tools-linux source=vcenter,vm=vm-12,address=name",
		"no-tools-win:windows@no-tools-win source=vcenter,vm=vm-13,address=name",
		"appl:linux@appl.example.com source=vcenter,vm=vm-16,address=name",
	}
	if strings.Join(s, "\n") != strings.Join(want, "\n") {
		t.Errorf("devices:\n%s", strings.Join(s, "\n"))
	}
	why := map[string]string{}
	for _, k := range skipped {
		why[k.Name] = k.Reason
	}
	for name, frag := range map[string]string{"mac": "darwin", "mystery": "OTHER_64", "off": "not powered on"} {
		if !strings.Contains(why[name], frag) {
			t.Errorf("%s: %q (want %q)", name, why[name], frag)
		}
	}
}
