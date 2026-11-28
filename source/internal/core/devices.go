package core

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"netdir/device"
)

// devHealth keeps every device's health: the controller of a device's gateway checks it (devicehealth.go) and every node
// shows the results of all of them.  Started in main.
var DevHealth = device.NewMonitor()

func (s *Supervisor) DeviceInventory() ([]device.Device, []device.Credential) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dc == nil {
		return nil, nil
	}
	return s.Dc.EffectiveDevices(), append([]device.Credential(nil), s.Dc.Settings.DeviceCredentials...)
}

// deviceTuning is how often the devices are looked at (settings.device_check_s, device_facts_min, device_live_check_s, device_live_facts_min).
func (s *Supervisor) DeviceTuning() device.Tuning {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Dc == nil {
		return device.Tuning{}
	}
	st := &s.Dc.Settings
	return device.Tuning{Reach: time.Duration(st.DeviceCheckSec) * time.Second, Facts: time.Duration(st.DeviceFactsMin) * time.Minute,
		LiveReach: time.Duration(st.DeviceLiveCheckSec) * time.Second, LiveFacts: time.Duration(st.DeviceLiveFactsMin) * time.Minute}
}

// expandGatewayTargets replaces each term gateway:N of a target with the names of that gateway's devices, so device.Select
// knows nothing about gateways.  A gateway that does not exist, or has no device, is an error, like any term that picks nothing.
func (s *Supervisor) ExpandGatewayTargets(target string) (string, error) {
	if !strings.Contains(target, "gateway:") {
		return target, nil
	}
	return ExpandGatewayTargetsIn(s.Config(), target)
}

// expandGatewayTargetsIn is expandGatewayTargets for a configuration at hand (Mgmt.deviceChange has one).
func ExpandGatewayTargetsIn(dc *DaemonConfig, target string) (string, error) {
	if !strings.Contains(target, "gateway:") {
		return target, nil
	}
	var out []string
	for _, term := range strings.Split(target, ",") {
		term = strings.TrimSpace(term)
		id, ok := strings.CutPrefix(term, "gateway:")
		if !ok {
			out = append(out, term)
			continue
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			return "", fmt.Errorf("target %q: gateway:N takes the gateway's group number", term)
		}
		var g *GroupConfig
		for i := range dc.Groups {
			if dc.Groups[i].GroupID == n {
				g = &dc.Groups[i]
			}
		}
		if g == nil {
			return "", fmt.Errorf("target %q: there is no gateway %d", term, n)
		}
		if len(g.Devices) == 0 {
			return "", fmt.Errorf("target %q: gateway %d has no devices", term, n)
		}
		out = append(out, g.Devices...)
	}
	return strings.Join(out, ","), nil
}
