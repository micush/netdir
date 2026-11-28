package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"netdir/device"
)

// Network Directors chained: a device of the platform netdir is another Network Director (its MCP key as the credential), and the
// devices it reaches show up here like any other device, in the Devices page and as a target of every device request.
//
//	clients ▸ netdir1 ▸ netdir2 ▸ technitium
//	                  ▸ netdir3 ▸ observium
//	                            ▸ netdir4 ▸ vcenter
//
// Links go from the director above to the one below (the address and the key are the device's), so a firewall only has to allow
// that direction.  Each director keeps the logins of its own devices and nothing else: a request for a device below goes down
// to the director that has it, which asks the device, hides what must not leave it, and answers up the same way.  The index of
// what is below comes from the directors' list_devices, kept for downTTL and refreshed in the background.  Reads go down for any
// target; a change or a capture goes down for a device named in its target (never for all, a tag or a platform), and the key of the
// link decides whether the director below allows it.

const (
	downTTL        = 20 * time.Second // a look at the directors below is this fresh when someone asks
	downBackground = 60 * time.Second // and this often when nobody does, so a deep chain is ready when the first request comes
	DownTimeout    = 8 * time.Second  // one director's list_devices
	downMaxDepth   = 6                // Network Directors in a chain, this one included
	DownHopSlack   = 15 * time.Second // more time per director a request goes through
)

// RemoteDevice is a device reached through a Network Director that is a device here.
type RemoteDevice struct {
	Name     string   `json:"name"`     // as it is listed and asked here (name@director when its own name is taken)
	Orig     string   `json:"orig"`     // its name on the director that is asked
	Platform string   `json:"platform"` // the device's own platform
	Address  string   `json:"address,omitempty"`
	Port     int      `json:"port,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
	Via      []string `json:"via"`            // Via[0] is the device here that is the Network Director; the rest are as each director names the next
	Inst     string   `json:"inst,omitempty"` // the installation that has the device's login
	Path     []string `json:"path,omitempty"` // the installations a request goes through, the next hop first and the owner last (this one's own is never in it: see buildRemote)
	Status   string   `json:"status,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

var Down struct {
	Mu   sync.Mutex        `json:"-"`
	At   time.Time         `json:"-"`
	List []RemoteDevice    `json:"-"`
	Errs map[string]string `json:"-"`
	done chan struct{}     // open while a look is running
}

// instanceID names this installation (the whole cluster, or the node when it is alone) without giving the cluster secret away.  It
// tells a loop of directors from another device with the same address.  Empty in tests without a cluster.
func InstanceID() string { return InstanceOf() }

// instanceOf is instanceID's work (a test replaces it).
var InstanceOf = func() string {
	if HealthCl == nil {
		return ""
	}
	sec := HealthCl.NodeSecret()
	if len(sec) == 0 {
		return ""
	}
	h := sha256.Sum256(append([]byte("netdir instance\x00"), sec...))
	return hex.EncodeToString(h[:6])
}

// directorsHere are the enabled devices of the platform netdir.
func DirectorsHere(devs []device.Device) []device.Device {
	var out []device.Device
	for _, d := range devs {
		if d.Platform == "netdir" && !d.Disabled {
			out = append(out, d)
		}
	}
	return out
}

type downPart struct {
	dir   device.Device
	below []device.Below
	err   error
}

// buildRemote makes the index from what each director listed: a device reached two ways is listed once (the shorter way), one that
// came back to this installation is dropped, a chain that is too long is cut, and a name that is taken is qualified.
func buildRemote(local []device.Device, parts []downPart, self string) []RemoteDevice {
	type cand struct {
		RemoteDevice
		key string
	}
	var cands []cand
	for _, p := range parts {
		for _, b := range p.below {
			if (self != "" && b.Inst == self) || len(b.Via)+2 > downMaxDepth || (self != "" && slices.Contains(b.Path, self)) {
				continue // its own, a chain that is too long, or one that goes through this installation (a list of a neighbor that is not up to date)
			}
			via := append([]string{p.dir.Name}, b.Via...)
			key := fmt.Sprintf("%s|%s|%s|%d", b.Inst, b.Platform, strings.ToLower(b.Address), b.Port)
			if b.Inst == "" {
				key += "|" + via[len(via)-1] + "|" + b.Name // an owner that does not say who it is: only the same name on the same director is the same device
			}
			cands = append(cands, cand{RemoteDevice{Name: b.Name, Orig: b.Name, Platform: b.Platform, Address: b.Address, Port: b.Port, Tags: b.Tags,
				Disabled: b.Disabled, Via: via, Inst: b.Inst, Path: b.Path, Status: b.Status, Detail: b.Detail}, key})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if len(cands[i].Via) != len(cands[j].Via) {
			return len(cands[i].Via) < len(cands[j].Via)
		}
		if cands[i].Via[0] != cands[j].Via[0] {
			return cands[i].Via[0] < cands[j].Via[0]
		}
		return strings.ToLower(cands[i].Name) < strings.ToLower(cands[j].Name)
	})
	taken := map[string]bool{}
	for _, d := range local {
		taken[strings.ToLower(d.Name)] = true
	}
	seen := map[string]bool{}
	var out []RemoteDevice
	for _, c := range cands {
		if seen[c.key] {
			continue
		}
		seen[c.key] = true
		r := c.RemoteDevice
		if taken[strings.ToLower(r.Name)] {
			r.Name = r.Orig + "@" + r.Via[len(r.Via)-1]
			for n := 2; taken[strings.ToLower(r.Name)]; n++ {
				r.Name = fmt.Sprintf("%s@%s#%d", r.Orig, r.Via[len(r.Via)-1], n)
			}
		}
		taken[strings.ToLower(r.Name)] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// lookBelow asks every director that is a device here for what it reaches.
func (s *Supervisor) lookBelow() {
	devs, creds := s.DeviceInventory()
	dirs := DirectorsHere(devs)
	cred := map[string]device.Credential{}
	for _, c := range creds {
		cred[c.Name] = c
	}
	parts := make([]downPart, len(dirs))
	var wg sync.WaitGroup
	for i, d := range dirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parts[i].dir = d
			ctx, cancel := context.WithTimeout(context.Background(), DownTimeout)
			defer cancel()
			drv, err := device.Open(d, cred[d.Credential])
			if err != nil {
				parts[i].err = err
				return
			}
			defer drv.Close(ctx)
			ds, ok := drv.(device.Downstream)
			if !ok {
				parts[i].err = device.ErrUnsupported
				return
			}
			_, parts[i].below, parts[i].err = ds.Below(ctx)
		}()
	}
	wg.Wait()
	errs := map[string]string{}
	var good []downPart
	for _, p := range parts {
		if p.err != nil {
			errs[p.dir.Name] = p.err.Error()
			continue
		}
		good = append(good, p)
	}
	list := buildRemote(devs, good, InstanceID())
	Down.Mu.Lock()
	Down.List, Down.Errs, Down.At = list, errs, time.Now()
	close(Down.done)
	Down.done = nil
	Down.Mu.Unlock()
}

// remoteDevices is the index of the devices below the directors, from the last look; when that is older than downTTL (or force) a new
// look starts, and the call waits up to wait for it (an index that has never been made is empty until then).
func (s *Supervisor) RemoteDevices(wait time.Duration, force bool) ([]RemoteDevice, map[string]string) {
	devs, _ := s.DeviceInventory()
	if len(DirectorsHere(devs)) == 0 {
		Down.Mu.Lock()
		Down.List, Down.Errs = nil, nil
		Down.Mu.Unlock()
		return nil, nil
	}
	Down.Mu.Lock()
	stale := force || time.Since(Down.At) > downTTL
	if stale && Down.done == nil {
		Down.done = make(chan struct{})
		go s.lookBelow()
	}
	ch := Down.done
	Down.Mu.Unlock()
	if stale && ch != nil && wait > 0 {
		select {
		case <-ch:
		case <-time.After(wait):
		}
	}
	Down.Mu.Lock()
	defer Down.Mu.Unlock()
	return append([]RemoteDevice(nil), Down.List...), Down.Errs
}

// downstreamLoop keeps the index warm: each director looks at the ones below it every downBackground, so a chain is ready bottom up
// before the first request.  Started in main.
func DownstreamLoop(ctx context.Context, s *Supervisor) {
	t := time.NewTicker(downBackground)
	defer t.Stop()
	for {
		s.RemoteDevices(0, true)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// remoteAsDevices lists the index as devices, for device.Select.
func RemoteAsDevices(rem []RemoteDevice) []device.Device {
	out := make([]device.Device, len(rem))
	for i, r := range rem {
		out[i] = device.Device{Name: r.Name, Platform: r.Platform, Address: r.Address, Port: r.Port, Tags: r.Tags, Disabled: r.Disabled}
	}
	return out
}

// splitRemote takes the devices below a director out of the target of a change or a capture: only a name picks them (a change for
// "all", a tag or a platform is for this director's own devices, as before), and the rest of the target is what stays here.
func SplitRemote(target string) (string, []RemoteDevice) {
	Down.Mu.Lock()
	list := Down.List
	Down.Mu.Unlock()
	var local []string
	var rem []RemoteDevice
	for _, term := range strings.Split(target, ",") {
		term = strings.TrimSpace(term)
		found := false
		for _, r := range list {
			if strings.EqualFold(term, r.Name) {
				rem, found = append(rem, r), true
				break
			}
		}
		if !found && term != "" {
			local = append(local, term)
		}
	}
	return strings.Join(local, ","), rem
}

func ToStr(v any) string { s, _ := v.(string); return s }

// askBelow runs a read on the devices of picked that are in rem, each group on the director it is reached through, and puts every answer
// into got under the lower-case name asked here.
func (s *Supervisor) AskBelow(ctx context.Context, picked []device.Device, rem []RemoteDevice, creds []device.Credential, dirs []device.Device,
	op, cmd string, to time.Duration, got map[string]device.Result) {
	byName := map[string]RemoteDevice{}
	for _, r := range rem {
		byName[strings.ToLower(r.Name)] = r
	}
	dirOf := map[string]device.Device{}
	for _, d := range dirs {
		dirOf[d.Name] = d
	}
	cred := map[string]device.Credential{}
	for _, c := range creds {
		cred[c.Name] = c
	}
	groups := map[string][]RemoteDevice{}
	for _, p := range picked {
		if r, ok := byName[strings.ToLower(p.Name)]; ok {
			groups[r.Via[0]] = append(groups[r.Via[0]], r)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for dirName, rs := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fail := func(msg string) {
				mu.Lock()
				defer mu.Unlock()
				for _, r := range rs {
					got[strings.ToLower(r.Name)] = device.Result{Device: r.Name, Platform: r.Platform, Error: msg}
				}
			}
			dir, ok := dirOf[dirName]
			if !ok {
				fail("the Network Director " + dirName + " is not in the inventory (enabled)")
				return
			}
			deepest := 1
			names := make([]string, len(rs))
			orig := map[string]RemoteDevice{}
			for i, r := range rs {
				names[i] = r.Orig
				orig[strings.ToLower(r.Orig)] = r
				deepest = max(deepest, len(r.Via))
			}
			cctx, cancel := context.WithTimeout(ctx, to+time.Duration(deepest)*DownHopSlack)
			defer cancel()
			drv, err := device.Open(dir, cred[dir.Credential])
			if err != nil {
				fail(err.Error())
				return
			}
			defer drv.Close(cctx)
			ds, ok := drv.(device.Downstream)
			if !ok {
				fail(device.ErrUnsupported.Error())
				return
			}
			res, err := ds.Ask(cctx, op, names, cmd)
			if err != nil {
				fail(dirName + ": " + err.Error())
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, x := range res {
				r, ok := orig[strings.ToLower(x.Device)]
				if !ok {
					continue
				}
				x.Device = r.Name
				got[strings.ToLower(r.Name)] = x
			}
			for _, r := range rs {
				if _, ok := got[strings.ToLower(r.Name)]; !ok {
					got[strings.ToLower(r.Name)] = device.Result{Device: r.Name, Platform: r.Platform, Error: dirName + " did not answer for it"}
				}
			}
		}()
	}
	wg.Wait()
}
