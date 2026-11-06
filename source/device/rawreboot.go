package device

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Reboots.  A restart is a change the daemon accepts on every platform that has a way to ask for one in its API: the request is
// matched exactly (method, path and, where the platform needs it, the body), so only a reboot gets past the guards that refuse the
// rest of the management tree.  What is different from other changes: nothing is read before or after it (the device is going
// away), the usual "does it still answer" check and the put-back are skipped, and a connection that ends after the request was
// sent counts as the device restarting.  Save writes the configuration first, where the platform has such a step.
//
//	iosxe       POST /restconf/operations/Cisco-IOS-XE-rpc:reload
//	aoscx       POST /rest/<version>/boot?image=primary|secondary
//	fortios     POST /api/v2/monitor/system/os/reboot
//	bigip       POST /mgmt/tm/sys with {"command":"reboot"}
//	meraki      POST /devices/<serial>/reboot
//	proxmox     POST /nodes/<node>/status with {"command":"reboot"}
//	panos       method "reboot" (the operational command request restart system)
//	eos, nxos   the one line "reload" (also "reload now")
//
// Not offered: nios, technitium, afc, dnsdir, ntpdir, observium and entra have no restart in the API this driver uses.

var (
	merakiRebootRE = regexp.MustCompile(`^/devices/[A-Za-z0-9-]+/reboot$`)
	reloadLineRE   = regexp.MustCompile(`(?i)^reload(\s+(now|force))?$`)
)

func isPost(r Raw) bool { return strings.EqualFold(r.Method, http.MethodPost) }

func bodyCommand(r Raw) string {
	var m map[string]any
	if json.Unmarshal([]byte(r.Body), &m) != nil {
		return ""
	}
	return strings.ToLower(str(m["command"]))
}

func iosxeReboot(r Raw) bool {
	return isPost(r) && strings.EqualFold(r.Path, "/restconf/operations/Cisco-IOS-XE-rpc:reload")
}

func aoscxReboot(root string) func(Raw) bool {
	return func(r Raw) bool {
		p, q, _ := strings.Cut(r.Path, "?")
		if !isPost(r) || p != root+"boot" {
			return false
		}
		v, err := url.ParseQuery(q)
		return err == nil && (q == "" || v.Get("image") == "primary" || v.Get("image") == "secondary") && len(v) <= 1
	}
}

func fortiosReboot(r Raw) bool {
	return isPost(r) && r.Path == "/api/v2/monitor/system/os/reboot"
}

func bigipReboot(r Raw) bool {
	p := strings.TrimSuffix(r.Path, "/")
	return isPost(r) && p == "/mgmt/tm/sys" && bodyCommand(r) == "reboot"
}

func merakiReboot(r Raw) bool { return isPost(r) && merakiRebootRE.MatchString(r.Path) }

func pveReboot(r Raw) bool {
	segs := strings.Split(strings.Trim(r.Path, "/"), "/")
	return isPost(r) && len(segs) == 3 && segs[0] == "nodes" && pveNodeRE.MatchString(segs[1]) && segs[2] == "status" && bodyCommand(r) == "reboot"
}

// rebootLine says whether the lines are one reload command, and returns it as sent.
func rebootLine(lines []string) (string, bool) {
	if len(lines) != 1 {
		return "", false
	}
	l := strings.Join(strings.Fields(lines[0]), " ")
	if !reloadLineRE.MatchString(l) {
		return "", false
	}
	return "reload now", true
}

// connEnded says whether an error is the connection closing under a request that went out: what a restarting device does.
func connEnded(err error) bool {
	if err == nil {
		return false
	}
	var se *statusError
	if errors.As(err, &se) {
		return false
	}
	s := strings.ToLower(err.Error())
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(s, "eof") || strings.Contains(s, "connection reset") ||
		strings.Contains(s, "closed") || strings.Contains(s, "broken pipe")
}

const rebootNote = "a restart was requested: the device does not answer for a few minutes, and nothing was read back"
