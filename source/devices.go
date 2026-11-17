package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"netdir/device"
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
	deviceParallel = 16               // devices asked at once
	deviceTimeout  = 30 * time.Second // per device, per request
	deviceConfigTO = 90 * time.Second // a whole configuration can take a while on a big box
)

// devHealth keeps every device's health: the controller of a device's gateway checks it (devicehealth.go) and every node
// shows the results of all of them.  Started in main.
var devHealth = device.NewMonitor()

// deviceInventory is a copy of the inventory and the credentials.
// offWhy says why a device is refused: "is disabled …" or, for one on no gateway, "is on no gateway …".
func offWhy(d device.Device) string {
	if d.Unattached {
		return "is on no gateway: add it to a gateway first (Topology ▸ right-click the gateway ▸ Add device)"
	}
	return "is disabled: enable it first (Configure ▸ Devices)"
}

func (s *Supervisor) deviceInventory() ([]device.Device, []device.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dc == nil {
		return nil, nil
	}
	return s.dc.effectiveDevices(), append([]device.Credential(nil), s.dc.Settings.DeviceCredentials...)
}

// deviceTuning is how often the devices are looked at (settings.device_check_s, device_facts_min, device_live_check_s, device_live_facts_min).
func (s *Supervisor) deviceTuning() device.Tuning {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dc == nil {
		return device.Tuning{}
	}
	st := &s.dc.Settings
	return device.Tuning{Reach: time.Duration(st.DeviceCheckSec) * time.Second, Facts: time.Duration(st.DeviceFactsMin) * time.Minute,
		LiveReach: time.Duration(st.DeviceLiveCheckSec) * time.Second, LiveFacts: time.Duration(st.DeviceLiveFactsMin) * time.Minute}
}

func (w *WebServer) handleDevices(rw http.ResponseWriter, r *http.Request, s *session) {
	health := deviceHealth(true) // someone is looking: the checks speed up
	devs, _ := w.status.sup.deviceInventory()
	sc := scopeOf(s)
	devs = sc.filter(devs) // an MCP caller limited to some devices (devscope.go) sees only those
	if devs == nil {
		devs = []device.Device{}
	}
	if sc.limited() {
		keep := map[string]device.Health{}
		for _, d := range devs {
			if h, ok := health[d.Name]; ok {
				keep[d.Name] = h
			}
		}
		health = keep
	}
	// remote: the devices below the Network Directors that are devices here (downstream.go), which a Network Director above lists in turn
	remote, rerrs := w.status.sup.remoteDevices(1500*time.Millisecond, false)
	remote = sc.filterRemote(remote)
	if remote == nil {
		remote = []RemoteDevice{}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"devices": devs, "platforms": device.Platforms(), "health": health,
		"remote": remote, "remote_errors": rerrs, "instance": instanceID()}})
}

// deviceOps are the requests a device can be asked; the bool says the op hands over secrets (refused to read-only).
var deviceOps = map[string]bool{"facts": false, "interfaces": false, "neighbors": false, "neighbor_details": false, "ports": false, "routes": false, "routing": false, "firewall": false, "resources": false, "api": false, "api_catalog": false, "vlans": false, "show": false, "config": true}

func (w *WebServer) handleDeviceQuery(rw http.ResponseWriter, r *http.Request, s *session) {
	lookAtDevices()
	q := r.URL.Query()
	op := q.Get("op")
	secret, known := deviceOps[op]
	if !known {
		jsonError(rw, http.StatusBadRequest, "op: facts, interfaces, ports, neighbors, neighbor_details, routes, routing, firewall, resources, vlans, api, api_catalog, show or config")
		return
	}
	if secret && s.readOnly && !s.mcp { // an MCP caller, read-only or not, gets the configuration with its secrets hidden (below)
		jsonError(rw, http.StatusForbidden, "a device's configuration holds its secrets: not for a read-only account")
		return
	}
	cmd := ""
	if op == "api" {
		var err error
		if cmd, err = device.CheckAPIPath(q.Get("path")); err != nil {
			jsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
	}
	if op == "show" {
		var err error
		if cmd, err = device.CheckShow(q.Get("cmd")); err != nil {
			jsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
	}
	devs, creds := w.status.sup.deviceInventory()
	sc := scopeOf(s)
	allDevs := devs // the whole inventory: a Network Director below is asked with the logins of all of it
	devs = sc.filter(devs)
	rem, _ := w.status.sup.remoteDevices(2*time.Second, false)
	rem = sc.filterRemote(rem)
	if len(devs) == 0 && len(rem) == 0 {
		jsonError(rw, http.StatusNotFound, "no devices are configured (settings.devices)")
		return
	}
	target, err := w.status.sup.expandGatewayTargets(q.Get("target"))
	if err != nil {
		jsonError(rw, http.StatusBadRequest, err.Error())
		return
	}
	picked, err := device.Select(append(append([]device.Device(nil), devs...), remoteAsDevices(rem)...), target)
	if err != nil && len(directorsHere(allDevs)) > 0 {
		// a name below a Network Director that the index does not have yet: look again now, and wait for it
		rem, _ = w.status.sup.remoteDevices(downTimeout, true)
		rem = sc.filterRemote(rem)
		picked, err = device.Select(append(append([]device.Device(nil), devs...), remoteAsDevices(rem)...), target)
	}
	if err != nil {
		jsonError(rw, http.StatusBadRequest, err.Error())
		return
	}
	if op == "api" && s.mcp && !s.raw {
		// what over MCP may not be read is the platform's to say: another platform's words for secrets refuse what is none here
		for _, d := range picked {
			if err = device.CheckAPIPathMCPFor(d.Platform, cmd); err != nil {
				jsonError(rw, http.StatusForbidden, err.Error())
				return
			}
		}
	}
	to := deviceTimeout
	if op == "config" || op == "routes" || op == "routing" || op == "firewall" || op == "api" || op == "api_catalog" || op == "resources" || op == "vlans" || op == "ports" {
		to = deviceConfigTO
	}
	infof("devices: %q asked %s of %s (%d devices)", s.user, opLabel(op, cmd), q.Get("target"), len(picked))
	isRemote := map[string]bool{}
	for _, x := range rem {
		isRemote[strings.ToLower(x.Name)] = true
	}
	var here []device.Device
	for _, p := range picked {
		if !isRemote[strings.ToLower(p.Name)] {
			here = append(here, p)
		}
	}
	got := map[string]device.Result{}
	var gwg sync.WaitGroup
	if len(here) < len(picked) {
		gwg.Add(1)
		go func() {
			defer gwg.Done()
			w.status.sup.askBelow(r.Context(), picked, rem, creds, directorsHere(allDevs), op, cmd, to, got)
		}()
	}
	// in a cluster a device is asked by the node that checks it: the devices of another site are handed to a node of that site, so the
	// request comes from where the device is.  A node that does not answer is skipped: this node asks those devices itself.
	var viaMu sync.Mutex
	via := map[string]device.Result{}
	var failedVia []device.Device
	if !s.hop && clusterOn() {
		var mine []device.Device
		byNode := map[string][]device.Device{}
		for _, d := range here {
			if addr := checkerOf(d.Name); addr != "" {
				byNode[addr] = append(byNode[addr], d)
			} else {
				mine = append(mine, d)
			}
		}
		here = mine
		for addr, ds := range byNode {
			gwg.Add(1)
			go func(addr string, ds []device.Device) {
				defer gwg.Done()
				got, err := askNodeDevices(r.Context(), addr, q, ds, s, w.ro(s), to)
				viaMu.Lock()
				defer viaMu.Unlock()
				if err != nil {
					warnf("devices: node %s could not be asked for %d devices (%v): asking them from here", addr, len(ds), err)
					failedVia = append(failedVia, ds...)
					return
				}
				for k, v := range got {
					via[k] = v
				}
			}(addr, ds)
		}
	}
	// an assistant often asks the same thing twice: what a device answered a moment ago is given again, with its age (answercache.go)
	byLocal := map[string]device.Result{}
	keys := map[string]string{}
	if answerCacheable(s, op, cmd, q.Get("fresh")) {
		var miss []device.Device
		var hs map[string]device.Health
		if op == "facts" {
			hs = deviceHealth(false)
		}
		for _, d := range here {
			if r, ok := factsFromMonitor(d, hs); ok {
				byLocal[strings.ToLower(d.Name)] = r
				continue
			}
			c, ok := credByName(creds, d.Credential)
			if !ok {
				miss = append(miss, d)
				continue
			}
			k := device.AnswerKey(d, c, answerMode(s), op, cmd)
			if r, age, hit := device.Answers.Get(k); hit {
				secs := int(age.Seconds())
				r.MS, r.Reused, r.CachedSecs = 0, false, &secs
				byLocal[strings.ToLower(d.Name)] = r
				continue
			}
			keys[strings.ToLower(d.Name)] = k
			miss = append(miss, d)
		}
		here = miss
	}
	local := device.FanoutReuse(r.Context(), here, creds, deviceParallel, to, func(ctx context.Context, d device.Driver) (v any, err error) {
		device.RunRaw(s.raw, func() { v, err = runDeviceOp(ctx, d, op, cmd, s.readOnly, s.mcp && !s.raw) })
		return v, err
	})
	gwg.Wait()
	for k, v := range via {
		byLocal[k] = v
	}
	if len(failedVia) > 0 {
		for _, x := range device.FanoutReuse(r.Context(), failedVia, creds, deviceParallel, to, func(ctx context.Context, d device.Driver) (v any, err error) {
			device.RunRaw(s.raw, func() { v, err = runDeviceOp(ctx, d, op, cmd, s.readOnly, s.mcp && !s.raw) })
			return v, err
		}) {
			byLocal[strings.ToLower(x.Device)] = x
		}
	}
	for _, x := range local {
		k := strings.ToLower(x.Device)
		byLocal[k] = x
		if ck := keys[k]; ck != "" {
			device.Answers.Put(ck, x, answerLife)
		}
	}
	res := make([]device.Result, 0, len(picked))
	for _, p := range picked {
		k := strings.ToLower(p.Name)
		if x, ok := got[k]; ok {
			res = append(res, x)
		} else if x, ok := byLocal[k]; ok {
			res = append(res, x)
		}
	}
	failed := 0
	if s.mcp && !s.raw && op == "config" { // every answer, also one relayed from a gateway below, goes through the shared secret filter
		for i := range res {
			res[i].Data = device.RedactConfigValue(res[i].Data)
		}
	}
	for _, x := range res {
		if !x.OK {
			failed++
		}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"op": op, "asked": len(res), "failed": failed, "results": res}})
}

// expandGatewayTargets replaces each term gateway:N of a target with the names of that gateway's devices, so device.Select
// knows nothing about gateways.  A gateway that does not exist, or has no device, is an error, like any term that picks nothing.
func (s *Supervisor) expandGatewayTargets(target string) (string, error) {
	if !strings.Contains(target, "gateway:") {
		return target, nil
	}
	return expandGatewayTargetsIn(s.config(), target)
}

// expandGatewayTargetsIn is expandGatewayTargets for a configuration at hand (Mgmt.deviceChange has one).
func expandGatewayTargetsIn(dc *DaemonConfig, target string) (string, error) {
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

func opLabel(op, cmd string) string {
	if cmd != "" {
		return op + " " + strings.TrimSpace(cmd)
	}
	return op
}

// mcpDeviceTool is the MCP tool that asks the devices of a target for op (GET /api/devices/query).
func mcpDeviceTool(name, title, op, desc string) mcpTool {
	props := []mcpProp{{name: "target", typ: "string", required: true,
		desc: "The devices: a name, tag:TAG, platform:PLATFORM, gateway:N (the devices of gateway N) or \"all\", several separated by commas (list_devices)."}}
	if op == "api" {
		props = append(props, mcpProp{name: "path", typ: "string", required: true, desc: "The path on the device's own API, e.g. /restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces or /api/v2/monitor/system/status, /api/mo/sys.json, /rest/v10.09/system, /wapi/v2.12/network, /eapi/show/version, /api/zones/list or /api/?type=op&cmd=<show><system><info></info></system></show>; device_api_catalog says what a device offers."})
	}
	if op == "show" {
		props = append(props, mcpProp{name: "command", typ: "string", required: true, desc: "The command, e.g. \"show ip interface brief\"."})
	}
	props = append(props, mcpProp{name: "fresh", typ: "boolean", desc: "Ask the devices again even if they answered the same a moment ago (an answer repeated within " + answerLife.String() + " comes from memory and says cached_s, its age)."})
	return mcpTool{name: name, title: title, noNode: true, idempotent: true,
		desc:  desc + " Every device is asked at once; each answer has ok, error, data and the time it took.",
		props: props,
		run: func(c *mcpCtx) (any, error) {
			q := url.Values{"target": {c.str("target")}, "op": {op}}
			if op == "show" {
				q.Set("cmd", c.str("command"))
			}
			if op == "api" {
				q.Set("path", c.str("path"))
			}
			if f, _ := c.flag("fresh"); f {
				q.Set("fresh", "1")
			}
			b, err := c.call("GET", "/api/devices/query?"+q.Encode(), nil, "")
			return asAny(b), err
		}}
}

func runDeviceOp(ctx context.Context, d device.Driver, op, cmd string, readOnly, mcp bool) (any, error) {
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
var relayDevices = func(ctx context.Context, addr string, req proxyReq) (*proxyResp, error) {
	if healthMg == nil || healthMg.cl == nil {
		return nil, errors.New("this node is not in a cluster")
	}
	return healthMg.cl.Relay(ctx, addr, req)
}

// askNodeDevices asks the node at addr the same device request for these devices (named exactly), as the caller made it: an MCP
// caller stays one there (no secrets), a read-only account stays read-only.  Whatever the caller could not use was dropped here already.
func askNodeDevices(ctx context.Context, addr string, q url.Values, devs []device.Device, s *session, ro bool, to time.Duration) (map[string]device.Result, error) {
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
	if f := strings.Fields(s.user); len(f) > 0 {
		user = f[0]
	}
	cctx, cancel := context.WithTimeout(ctx, to+10*time.Second)
	defer cancel()
	resp, err := relayDevices(cctx, addr, proxyReq{User: user, Method: http.MethodGet, Path: "/api/devices/query?" + v.Encode(), RO: ro, MCP: s.mcp, Raw: s.raw})
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
