package devices

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netdir/device"
	"netdir/internal/core"
)

// Managed devices: the switches and firewalls the gateway reaches for its callers (device/ has the drivers).  The
// inventory (settings.devices) and the logins (settings.device_credentials) are shared by the cluster like the rest of the settings
// block, so any node can answer for any device.  The GUI's API has two routes, and the MCP tools use them as every
// other tool uses the API, so the same rules apply:
//
//	GET /api/devices                     the inventory (never the credentials) and the platforms that have a driver
//	GET /api/devices/query?target=&op=   ask the devices target picks (device.Select; gateway:N is the devices of gateway N) for op, all at once
//
// Every op reads.  "config" (a device's whole configuration, which holds its own secrets) is refused to a read-only
// GUI account, as the GUI's own configuration versions are.  An MCP caller gets it with the secrets hidden by the shared
// filter (device.RedactConfig; Configure ▸ Privacy ▸ Secret words).

const (
	DeviceParallel = 16               // devices asked at once
	DeviceTimeout  = 30 * time.Second // per device, per request
	DeviceConfigTO = 90 * time.Second // a whole configuration can take a while on a big box
)

// deviceInventory is a copy of the inventory and the credentials.
// offWhy says why a device is refused: "is disabled …" or, for one on no gateway, "is on no gateway …".
func OffWhy(d device.Device) string {
	if d.Unattached {
		return "is on no gateway: add it to a gateway first (Topology ▸ right-click the gateway ▸ Add device)"
	}
	return "is disabled: enable it first (Configure ▸ Devices)"
}

// deviceOps are the requests a device can be asked; the bool says the op hands over secrets (refused to read-only).
var DeviceOps = map[string]bool{"facts": false, "interfaces": false, "neighbors": false, "neighbor_details": false, "ports": false, "routes": false, "routing": false, "firewall": false, "resources": false, "api": false, "api_catalog": false, "vlans": false, "show": false, "config": true}

func OpLabel(op, cmd string) string {
	if cmd != "" {
		return op + " " + strings.TrimSpace(cmd)
	}
	return op
}

func RunDeviceOp(ctx context.Context, d device.Driver, op, cmd string, readOnly, mcp bool) (any, error) {
	var v any
	var err error
	switch op {
	case "facts":
		v, err = d.Facts(ctx)
	case "interfaces":
		v, err = d.Interfaces(ctx)
	case "neighbors", "neighbor_details":
		var ns []device.Neighbor
		ns, err = d.Neighbors(ctx)
		if op == "neighbors" {
			for i := range ns {
				ns[i].Detail = nil
			}
		}
		v = ns
	case "ports":
		if p, ok := d.(device.Porter); ok {
			v, err = p.Ports(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "routes":
		if r, ok := d.(device.Router); ok {
			v, err = r.Routes(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "resources":
		if r, ok := d.(device.Resourcer); ok {
			v, err = r.Resources(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "vlans":
		if r, ok := d.(device.VLANer); ok {
			v, err = r.VLANs(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "api":
		a, ok := d.(device.APIer)
		if !ok {
			err = device.ErrUnsupported
			break
		}
		var text bool
		v, text, err = a.APIGet(ctx, cmd)
		if err == nil && text && (readOnly || mcp) {
			v, err = nil, errors.New("this path answers text (a file or a configuration) that can hold secrets: not for a read-only account or over MCP")
		}
	case "api_catalog":
		if a, ok := d.(device.APIer); ok {
			v, err = a.APICatalog(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "firewall":
		if r, ok := d.(device.Firewaller); ok {
			v, err = r.Firewall(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "routing":
		if r, ok := d.(device.Router); ok {
			v, err = r.Routing(ctx)
		} else {
			err = device.ErrUnsupported
		}
	case "config":
		v, err = d.Config(ctx)
		if err == nil && mcp {
			v = device.RedactConfigValue(v)
		}
	case "show":
		v, err = d.Show(ctx, cmd)
		if txt, ok := v.(string); ok && err == nil && mcp {
			v = device.RedactText(txt) // keys, passwords and communities never reach an MCP caller
		}
	default:
		return nil, errors.New("unknown op")
	}
	if errors.Is(err, device.ErrUnsupported) && op == "show" {
		return nil, errors.New("this platform's API runs no CLI commands; use facts, interfaces, ports, neighbors, routes or config (over MCP: device_config)")
	}
	return v, err
}

// relayDevices sends a request to another node (a variable so a test can stand in for the cluster).
var RelayDevices = func(ctx context.Context, addr string, req core.ProxyReq) (*core.ProxyResp, error) {
	if core.HealthCl == nil {
		return nil, errors.New("this node is not in a cluster")
	}
	return core.HealthCl.Relay(ctx, addr, req)
}

// askNodeDevices asks the node at addr the same device request for these devices (named exactly), as the caller made it: an MCP
// caller stays one there (no secrets), a read-only account stays read-only.  Whatever the caller could not use was dropped here already.
func AskNodeDevices(ctx context.Context, addr string, q url.Values, devs []device.Device, s *core.Session, ro bool, to time.Duration) (map[string]device.Result, error) {
	v := url.Values{}
	for k, vals := range q {
		v[k] = vals
	}
	names := make([]string, 0, len(devs))
	for _, d := range devs {
		names = append(names, d.Name)
	}
	v.Set("target", strings.Join(names, ","))
	user := "devices"
	if f := strings.Fields(s.User); len(f) > 0 {
		user = f[0]
	}
	cctx, cancel := context.WithTimeout(ctx, to+10*time.Second)
	defer cancel()
	resp, err := RelayDevices(cctx, addr, core.ProxyReq{User: user, Method: http.MethodGet, Path: "/api/devices/query?" + v.Encode(), RO: ro, MCP: s.Mcp, Raw: s.Raw})
	if err != nil {
		return nil, err
	}
	var out struct {
		OK   bool `json:"ok"`
		Data struct {
			Results []device.Result `json:"results"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || resp.Status != http.StatusOK || !out.OK {
		msg := out.Error
		if msg == "" {
			msg = "status " + strconv.Itoa(resp.Status)
		}
		return nil, errors.New(msg)
	}
	got := map[string]device.Result{}
	for _, x := range out.Data.Results {
		got[strings.ToLower(x.Device)] = x
	}
	return got, nil
}
