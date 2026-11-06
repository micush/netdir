package device

import "testing"

// every platform can be changed with device_change_raw: a new driver that cannot is a compile error here, and a new platform that is
// not listed fails the test.
var _ = []RawChanger{(*afc)(nil), (*aoscx)(nil), (*bigip)(nil), (*director)(nil), (*entra)(nil), (*eos)(nil), (*fortios)(nil), (*iosxe)(nil),
	(*meraki)(nil), (*nios)(nil), (*nxos)(nil), (*observium)(nil), (*panos)(nil), (*proxmox)(nil), (*technitium)(nil), (*ipfabric)(nil)}

func TestEveryPlatformIsWritable(t *testing.T) {
	covered := map[string]bool{"afc": true, "aoscx": true, "bigip": true, "dnsdir": true, "ntpdir": true, "entra": true, "eos": true, "fortios": true,
		"iosxe": true, "ipfabric": true, "meraki": true, "nios": true, "nxos": true, "observium": true, "panos": true, "panorama": true, "proxmox": true, "technitium": true}
	for _, p := range Platforms() {
		if !covered[p] {
			t.Errorf("platform %s is not in the list of writable drivers: give it a RawChange and add it here", p)
		}
		delete(covered, p)
	}
	for p := range covered {
		t.Errorf("platform %s is listed but not registered", p)
	}
}
