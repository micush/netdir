package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// A Network Director as a device is also a way to reach the devices it reaches.  Its list_devices tool answers the devices
// of its own inventory, the ones below the Network Directors it has as devices (remote), and the identity of its installation
// (instance).  A device request for one of them goes down to that director's own device_* tool with the device's name there, and
// that director (which holds the login, and hides the secrets of the answer) asks the device, or asks the director below it.

// Below is a device a Network Director reaches, as that director lists it.
type Below struct {
	// Name is the device's name on the director that was asked, Via the Network Directors between that one and the device (the
	// ones it asks in turn, nearest first, by the names the director above each has for it), Inst the installation that holds
	// the device's login (it tells a loop from another device with the same address).
	Name     string   `json:"name"`
	Platform string   `json:"platform"`
	Address  string   `json:"address,omitempty"`
	Port     int      `json:"port,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
	Via      []string `json:"via,omitempty"`
	Inst     string   `json:"inst,omitempty"`
	// Status and Detail are the health as the owning director sees it: ok, warn, bad or "" when it has not looked yet.
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Downstream is a driver whose device also reaches devices of its own: a Network Director.
type Downstream interface {
	// Below is the installation's identity and every device the director reaches, its own and those below it.
	Below(ctx context.Context) (string, []Below, error)
	// Ask runs a read on the named devices of that director (names as it has them) and answers each one's result.  op is one of the
	// device requests (facts, interfaces, ports, neighbors, neighbor_details, routes, routing, firewall, resources, vlans,
	// api_catalog, api with arg the path, show with arg the command).
	Ask(ctx context.Context, op string, names []string, arg string) ([]Result, error)
}

var _ Downstream = (*director)(nil)

var downstreamTool = map[string]string{"facts": "device_facts", "interfaces": "device_interfaces", "ports": "device_ports", "neighbors": "device_neighbors",
	"neighbor_details": "device_neighbor_details", "routes": "device_routes", "routing": "device_routing", "firewall": "device_firewall",
	"resources": "device_resources", "vlans": "device_vlans", "api_catalog": "device_api_catalog", "api": "device_api_get", "show": "device_show"}

func (m *director) Below(ctx context.Context) (string, []Below, error) {
	if m.kind != "net" {
		return "", nil, ErrUnsupported
	}
	v, err := m.callPlain(ctx, "list_devices", nil)
	if err != nil {
		return "", nil, err
	}
	var in struct {
		Instance string `json:"instance"`
		Devices  []struct {
			Name     string   `json:"name"`
			Platform string   `json:"platform"`
			Address  string   `json:"address"`
			Port     int      `json:"port"`
			Tags     []string `json:"tags"`
			Disabled bool     `json:"disabled"`
		} `json:"devices"`
		Remote []Below           `json:"remote"`
		Health map[string]Health `json:"health"`
	}
	b, _ := json.Marshal(v)
	if err := json.Unmarshal(b, &in); err != nil {
		return "", nil, fmt.Errorf("list_devices: %v", err)
	}
	var out []Below
	for _, d := range in.Devices {
		h := in.Health[d.Name]
		out = append(out, Below{Name: d.Name, Platform: d.Platform, Address: d.Address, Port: d.Port, Tags: d.Tags, Disabled: d.Disabled,
			Inst: in.Instance, Status: h.Status, Detail: h.Detail})
	}
	out = append(out, in.Remote...)
	return in.Instance, out, nil
}

func (m *director) Ask(ctx context.Context, op string, names []string, arg string) ([]Result, error) {
	if m.kind != "net" {
		return nil, ErrUnsupported
	}
	tool := downstreamTool[op]
	if tool == "" {
		return nil, fmt.Errorf("%s: not a request a Network Director passes on", op)
	}
	if len(names) == 0 {
		return nil, errors.New("no devices named")
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	args := map[string]any{"target": strings.Join(sorted, ",")}
	switch op {
	case "api":
		args["path"] = arg
	case "show":
		args["command"] = arg
	}
	v, err := m.callPlain(ctx, tool, args)
	if err != nil {
		return nil, err
	}
	var out struct {
		Results []Result `json:"results"`
	}
	b, _ := json.Marshal(v)
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %v", tool, err)
	}
	return out.Results, nil
}
