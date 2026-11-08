package device

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
)

// With NETDIR_LEAKCAPTURE=FILE the tests record everything every driver returns while they run, and the credentials the
// drivers were given, into FILE (JSON).  tools/leaktest.sh then feeds that to the masking test of package main, which checks
// that what an MCP caller is told at the strict level holds none of the addresses, MAC addresses, serial numbers and secrets
// of the test data.  Without the variable nothing is recorded and the drivers are not wrapped.

type leakRec struct {
	Platform string `json:"platform"`
	Op       string `json:"op"`
	Value    any    `json:"value,omitempty"`
	Err      string `json:"err,omitempty"`
}

var leak struct {
	sync.Mutex
	recs    []leakRec
	secrets map[string]bool
}

func leakAdd(plat, op string, v any, err error) {
	r := leakRec{Platform: plat, Op: op}
	if err != nil {
		r.Err = err.Error()
	}
	if v != nil {
		if b, e := json.Marshal(v); e == nil {
			_ = json.Unmarshal(b, &r.Value)
		}
	}
	leak.Lock()
	leak.recs = append(leak.recs, r)
	leak.Unlock()
}

type recDrv struct {
	Driver
	plat string
}

func (r recDrv) Facts(ctx context.Context) (Facts, error) {
	v, err := r.Driver.Facts(ctx)
	leakAdd(r.plat, "facts", v, err)
	return v, err
}
func (r recDrv) Interfaces(ctx context.Context) ([]Interface, error) {
	v, err := r.Driver.Interfaces(ctx)
	leakAdd(r.plat, "interfaces", v, err)
	return v, err
}
func (r recDrv) Neighbors(ctx context.Context) ([]Neighbor, error) {
	v, err := r.Driver.Neighbors(ctx)
	leakAdd(r.plat, "neighbors", v, err)
	return v, err
}
func (r recDrv) Config(ctx context.Context) (string, error) {
	v, err := r.Driver.Config(ctx)
	leakAdd(r.plat, "config", v, err)
	return v, err
}
func (r recDrv) Show(ctx context.Context, cmd string) (string, error) {
	v, err := r.Driver.Show(ctx, cmd)
	leakAdd(r.plat, "show", v, err)
	return v, err
}

// one mixin per optional interface; a wrapper embeds the ones its driver has, so it has exactly the driver's methods
type mx struct {
	d    Driver
	plat string
}
type mAPI struct{ mx }
type mRaw struct{ mx }
type mFW struct{ mx }
type mPort struct{ mx }
type mRoute struct{ mx }
type mRes struct{ mx }
type mVLAN struct{ mx }
type mChg struct{ mx }
type mUser struct{ mx }
type mCli struct{ mx }
type mCap struct{ mx }
type mDown struct{ mx }

func (m mAPI) APIGet(ctx context.Context, p string) (any, bool, error) {
	v, text, err := m.d.(APIer).APIGet(ctx, p)
	leakAdd(m.plat, "api_get", v, err)
	return v, text, err
}
func (m mAPI) APICatalog(ctx context.Context) (any, error) {
	v, err := m.d.(APIer).APICatalog(ctx)
	leakAdd(m.plat, "api_catalog", v, err)
	return v, err
}
func (m mRaw) RawChange(ctx context.Context, q Raw, dry bool) (RawResult, error) {
	v, err := m.d.(RawChanger).RawChange(ctx, q, dry)
	leakAdd(m.plat, "raw_change", v, err)
	return v, err
}
func (m mFW) Firewall(ctx context.Context) (Firewall, error) {
	v, err := m.d.(Firewaller).Firewall(ctx)
	leakAdd(m.plat, "firewall", v, err)
	return v, err
}
func (m mPort) Ports(ctx context.Context) ([]Port, error) {
	v, err := m.d.(Porter).Ports(ctx)
	leakAdd(m.plat, "ports", v, err)
	return v, err
}
func (m mRoute) Routes(ctx context.Context) ([]Route, error) {
	v, err := m.d.(Router).Routes(ctx)
	leakAdd(m.plat, "routes", v, err)
	return v, err
}
func (m mRoute) Routing(ctx context.Context) (Routing, error) {
	v, err := m.d.(Router).Routing(ctx)
	leakAdd(m.plat, "routing", v, err)
	return v, err
}
func (m mRes) Resources(ctx context.Context) (Resources, error) {
	v, err := m.d.(Resourcer).Resources(ctx)
	leakAdd(m.plat, "resources", v, err)
	return v, err
}
func (m mVLAN) VLANs(ctx context.Context) ([]VLAN, error) {
	v, err := m.d.(VLANer).VLANs(ctx)
	leakAdd(m.plat, "vlans", v, err)
	return v, err
}
func (m mChg) Change(ctx context.Context, c Change, dry bool) (ChangeResult, error) {
	v, err := m.d.(Changer).Change(ctx, c, dry)
	leakAdd(m.plat, "change", v, err)
	return v, err
}
func (m mUser) UserDevices(ctx context.Context, who string) (map[string]any, []map[string]any, error) {
	u, dv, err := m.d.(UserDeviceLooker).UserDevices(ctx, who)
	leakAdd(m.plat, "user_devices", map[string]any{"user": u, "devices": dv}, err)
	return u, dv, err
}
func (m mCli) ClientReport(ctx context.Context, q ClientQuery) (map[string]any, error) {
	v, err := m.d.(ClientReporter).ClientReport(ctx, q)
	leakAdd(m.plat, "client_report", v, err)
	return v, err
}
func (m mCap) Capture(ctx context.Context, r CaptureReq) (CaptureResult, error) {
	v, err := m.d.(Capturer).Capture(ctx, r)
	leakAdd(m.plat, "capture", v, err)
	return v, err
}

func (m mDown) Below(ctx context.Context) (string, []Below, error) {
	inst, v, err := m.d.(Downstream).Below(ctx)
	leakAdd(m.plat, "below", v, err)
	return inst, v, err
}
func (m mDown) Ask(ctx context.Context, op string, names []string, arg string) ([]Result, error) {
	v, err := m.d.(Downstream).Ask(ctx, op, names, arg)
	leakAdd(m.plat, "ask", v, err)
	return v, err
}

// wrapLeak returns a driver that records what it answers and has the methods of the driver it wraps; one for each set of
// optional interfaces the platforms have (a driver with another set is not wrapped, so its answers are not recorded).
func wrapLeak(plat string, drv Driver) Driver {
	m := mx{drv, plat}
	rd := recDrv{drv, plat}
	var set string
	add := func(ok bool, n string) {
		if ok {
			set += n + " "
		}
	}
	_, api := drv.(APIer)
	_, raw := drv.(RawChanger)
	_, fw := drv.(Firewaller)
	_, port := drv.(Porter)
	_, route := drv.(Router)
	_, res := drv.(Resourcer)
	_, vlan := drv.(VLANer)
	_, chg := drv.(Changer)
	_, user := drv.(UserDeviceLooker)
	_, cli := drv.(ClientReporter)
	_, capt := drv.(Capturer)
	_, down := drv.(Downstream)
	add(api, "api")
	add(raw, "raw")
	add(fw, "fw")
	add(port, "port")
	add(route, "route")
	add(res, "res")
	add(vlan, "vlan")
	add(chg, "chg")
	add(user, "user")
	add(cli, "cli")
	add(capt, "cap")
	add(down, "down")
	switch set {
	case "api raw fw port route res vlan chg cap ": // eos
		return struct {
			recDrv
			mAPI
			mRaw
			mFW
			mPort
			mRoute
			mRes
			mVLAN
			mChg
			mCap
		}{rd, mAPI{m}, mRaw{m}, mFW{m}, mPort{m}, mRoute{m}, mRes{m}, mVLAN{m}, mChg{m}, mCap{m}}
	case "api raw fw port route res vlan ": // fortios, nxos, panos
		return struct {
			recDrv
			mAPI
			mRaw
			mFW
			mPort
			mRoute
			mRes
			mVLAN
		}{rd, mAPI{m}, mRaw{m}, mFW{m}, mPort{m}, mRoute{m}, mRes{m}, mVLAN{m}}
	case "api raw port chg cli ": // meraki
		return struct {
			recDrv
			mAPI
			mRaw
			mPort
			mChg
			mCli
		}{rd, mAPI{m}, mRaw{m}, mPort{m}, mChg{m}, mCli{m}}
	case "api raw res ": // nios, technitium
		return struct {
			recDrv
			mAPI
			mRaw
			mRes
		}{rd, mAPI{m}, mRaw{m}, mRes{m}}
	case "api raw ": // afc, aviatrix, centreon, ipfabric, junos, proxmox
		return struct {
			recDrv
			mAPI
			mRaw
		}{rd, mAPI{m}, mRaw{m}}
	case "api raw fw port route res vlan cap ": // bigip
		return struct {
			recDrv
			mAPI
			mRaw
			mFW
			mPort
			mRoute
			mRes
			mVLAN
			mCap
		}{rd, mAPI{m}, mRaw{m}, mFW{m}, mPort{m}, mRoute{m}, mRes{m}, mVLAN{m}, mCap{m}}
	case "api raw user ": // entra
		return struct {
			recDrv
			mAPI
			mRaw
			mUser
		}{rd, mAPI{m}, mRaw{m}, mUser{m}}
	case "api raw port res ": // observium
		return struct {
			recDrv
			mAPI
			mRaw
			mPort
			mRes
		}{rd, mAPI{m}, mRaw{m}, mPort{m}, mRes{m}}
	case "api raw fw port route res vlan chg ": // aoscx, iosxe
		return struct {
			recDrv
			mAPI
			mRaw
			mFW
			mPort
			mRoute
			mRes
			mVLAN
			mChg
		}{rd, mAPI{m}, mRaw{m}, mFW{m}, mPort{m}, mRoute{m}, mRes{m}, mVLAN{m}, mChg{m}}
	case "api raw res cap down ": // dnsdir, ntpdir, netdir
		return struct {
			recDrv
			mAPI
			mRaw
			mRes
			mCap
			mDown
		}{rd, mAPI{m}, mRaw{m}, mRes{m}, mCap{m}, mDown{m}}
	}
	return drv
}

func init() {
	if os.Getenv("NETDIR_LEAKCAPTURE") == "" {
		return
	}
	leak.secrets = map[string]bool{}
	regMu.Lock()
	defer regMu.Unlock()
	for plat, f := range registry {
		plat, f := plat, f
		registry[plat] = func(d Device, c Credential) (Driver, error) {
			drv, err := f(d, c)
			if err != nil {
				return drv, err
			}
			leak.Lock()
			for _, s := range []string{c.Password, c.Token} {
				if len(s) >= 4 {
					leak.secrets[s] = true
				}
			}
			leak.Unlock()
			return wrapLeak(plat, drv), nil
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if p := os.Getenv("NETDIR_LEAKCAPTURE"); p != "" {
		var sec []string
		for s := range leak.secrets {
			sec = append(sec, s)
		}
		b, _ := json.Marshal(map[string]any{"records": leak.recs, "secrets": sec})
		_ = os.WriteFile(p, b, 0o600)
	}
	os.Exit(code)
}
