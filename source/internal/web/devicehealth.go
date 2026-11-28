package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

// handleDeviceHealth: GET /api/devices/health[?look=1] — the health this node holds of the devices it checks (what the other nodes ask).
func (w *WebServer) handleDeviceHealth(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	if r.URL.Query().Get("look") == "1" {
		core.DevHealth.Touch()
	}
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"health": core.DevHealth.Snapshot()}})
}

// handleDeviceRecheck: POST /api/devices/recheck {"name"} — ask that device again now, whatever its state: its facts are asked at
// once (one that refused a request is otherwise asked again every few minutes, and one nobody looks at every six hours) and the
// answer is its state from then on.  The page's right-click ▸ Network tools ▸ Recheck, after a login or a firewall rule was
// corrected.  The node that checks the device asks it, so another node hands the request to that one.  A read-only account cannot ask (it is
// a POST: authed refuses it); a caller limited to some devices (devscope.go) can ask only for those.
func (w *WebServer) HandleDeviceRecheck(rw http.ResponseWriter, r *http.Request, s *core.Session) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096)).Decode(&in); err != nil || in.Name == "" {
		core.JsonError(rw, http.StatusBadRequest, "name: the device to ask again")
		return
	}
	devs, creds := w.Status.Sup().DeviceInventory()
	var dev *device.Device
	for _, d := range devices.ScopeOf(s).Filter(devs) {
		if d.Name == in.Name {
			dev = &d
			break
		}
	}
	if dev == nil {
		core.JsonError(rw, http.StatusNotFound, "no such device: "+in.Name)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), devices.RecheckTimeout)
	defer cancel()
	if addr := devices.RecheckTarget(in.Name); addr != "" {
		user := "devices"
		if f := strings.Fields(s.User); len(f) > 0 { // "user via node" when this request was itself relayed: the user is the first word
			user = f[0]
		}
		body, _ := json.Marshal(map[string]string{"name": in.Name})
		resp, err := core.HealthCl.Relay(ctx, addr, core.ProxyReq{User: user, Method: http.MethodPost, Path: "/api/devices/recheck", CT: "application/json", Body: body, RO: w.ro(s)})
		if err != nil {
			core.JsonError(rw, http.StatusBadGateway, "the node that checks the device could not be asked: "+err.Error())
			return
		}
		core.PeerHealth.Mu.Lock()
		if e := core.PeerHealth.M[addr]; e != nil {
			e.At = time.Time{} // the next look at the devices asks that node again, not this node's few-second-old copy
		}
		core.PeerHealth.Mu.Unlock()
		ct := resp.CT
		if ct == "" {
			ct = "application/json"
		}
		rw.Header().Set("Content-Type", ct)
		rw.WriteHeader(resp.Status)
		rw.Write(resp.Body)
		return
	}
	var cred device.Credential
	for _, c := range creds {
		if c.Name == dev.Credential {
			cred = c
			break
		}
	}
	core.DevHealth.Touch() // someone is looking: the rounds that follow are the short ones
	h := core.DevHealth.Recheck(ctx, *dev, cred, time.Now())
	h.Facts = nil // the page wants the state and why, not the device's facts
	core.WriteJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"name": dev.Name, "health": h}})
}
