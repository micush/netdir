package devices

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"netdir/device"
	"netdir/internal/core"
)

// Troubleshoot a user: Entra says which devices the user has and which was used last, Meraki says where a device of that name was seen
// on the network in the last hours and how it did (device/meraki_clients.go lists what is read).
//
//	GET /api/devices/troubleshoot?user=joe.smith@contoso.com[&hours=6][&devices=1][&network=L_123][&entra=NAME][&meraki=NAME]
//	netdir --troubleshoot-user joe.smith@contoso.com [--troubleshoot-hours 6]
//	MCP device_troubleshoot_user
//
// It only reads, so a read-only account and an ro MCP key may use it.  The Entra device is the one of platform entra and the Meraki
// device the organization one (platform meraki without a serial); with several of either, entra= or meraki= names the one.  The two are
// matched by name: the device's name in Entra against the host name the client gave on the network (case and domain ignored).

func PickDevice(devs []device.Device, name, platform string, ok func(device.Device) bool) (device.Device, error) {
	var found []device.Device
	for _, d := range devs {
		if d.Platform != platform || d.Disabled || (ok != nil && !ok(d)) {
			continue
		}
		if name != "" && d.Name != name {
			continue
		}
		found = append(found, d)
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		if name != "" {
			return device.Device{}, fmt.Errorf("device %q: not an enabled %s device in the inventory", name, platform)
		}
		return device.Device{}, fmt.Errorf("no enabled %s device is configured", platform)
	}
	var n []string
	for _, d := range found {
		n = append(n, d.Name)
	}
	return device.Device{}, fmt.Errorf("several %s devices (%s): name one", platform, strings.Join(n, ", "))
}

// tsName is a name that may go into a log filter between quotes: an account name, a sign-in name, a host name.
var TsNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// tsShortUser is the account name of what was typed or found: "joe.smith" of joe.smith@contoso.com or of CORP\joe.smith.  Empty
// when it is not a name a filter can take (a name with spaces, an object ID).
func TsShortUser(names ...string) string {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if i := strings.LastIndexByte(n, '\\'); i >= 0 {
			n = n[i+1:]
		}
		if i := strings.IndexByte(n, '@'); i > 0 {
			n = n[:i]
		}
		if TsNameRE.MatchString(n) && !entraIDLike(n) {
			return n
		}
	}
	return ""
}

func entraIDLike(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// tsHostKey is a host name as two systems agree on it: lower case, without a domain.
func TsHostKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// pickLogDevice is the device whose logs are searched: the Panorama if there is one, else the firewall; name picks one.
func PickLogDevice(devs []device.Device, name string) (device.Device, error) {
	if name != "" {
		for _, plat := range []string{"panorama", "panos"} {
			if d, err := PickDevice(devs, name, plat, nil); err == nil {
				return d, nil
			}
		}
		return device.Device{}, fmt.Errorf("device %q: not an enabled panorama or panos device in the inventory", name)
	}
	d, err := PickDevice(devs, "", "panorama", nil)
	if err == nil || !strings.HasPrefix(err.Error(), "no enabled") {
		return d, err
	}
	if d, err = PickDevice(devs, "", "panos", nil); err != nil && strings.HasPrefix(err.Error(), "no enabled") {
		return d, errors.New("no enabled panorama or panos device is configured")
	}
	return d, err
}

const (
	TsVPNLogs     = 20 // GlobalProtect events read
	TsTrafficLogs = 50
	TsThreatLogs  = 20
	TsMaxAddrs    = 4
	TsMaxHosts    = 3
	TsTickets     = 3 // the newest tickets of the user read from a SMAX device
)

func UrlQ(s string) string { return url.QueryEscape(s) }

// ---- the CLI ----

func RunTroubleshootUser(sock, user, host, hours string) {
	args := map[string]any{}
	if user != "" {
		args["user"] = user
	}
	if host != "" {
		args["host"] = host
	}
	if hours != "" {
		args["hours"] = hours
	}
	var v any
	core.Decode(core.Op(sock, "device.troubleshoot", args), &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// shortCommand turns "netdir tshoot user NAME [HOURS]", "netdir tshoot host NAME [HOURS]" and the older "netdir tshoot NAME [HOURS]"
// (a user) into the flags they stand for; "troubleshoot" is the same word written out.  --tshoot alone, the node's troubleshooting
// bundle, is unchanged.  Anything else is returned as it was.
func ShortCommand(args []string) []string {
	if len(args) < 2 || args[0] != "tshoot" && args[0] != "troubleshoot" || strings.HasPrefix(args[1], "-") {
		return args
	}
	flag, rest := "--troubleshoot-user", args[1:]
	if (rest[0] == "user" || rest[0] == "host") && len(rest) >= 2 && !strings.HasPrefix(rest[1], "-") {
		if rest[0] == "host" {
			flag = "--troubleshoot-host"
		}
		rest = rest[1:]
	}
	out := []string{flag, rest[0]}
	rest = rest[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		out = append(out, "--troubleshoot-hours", rest[0])
		rest = rest[1:]
	}
	return append(out, rest...)
}
