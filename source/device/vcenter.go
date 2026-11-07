package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// VMware vCenter Server (https://developer.broadcom.com/xapis/vsphere-automation-api/latest/), through the vSphere Automation API:
// REST at https://HOST/api/... (vCenter 7.0 Update 2 and later; older releases serve /rest/... with their answers wrapped in
// {"value": ...}: the driver finds out by itself, and option api_style "api" or "rest" forces one).  The credential is a vCenter
// Single Sign-On user name (user@vsphere.local) and password: the driver creates a session (POST /api/session with the user and
// password in the Authorization header, never in a URL), sends the session ID in vmware-api-session-id, renews an expired session
// once and deletes the session when it is closed.
//
// vCenter is a manager, not a switch: the "device" is the vCenter server.
//
//   - Facts: the release and build.  Interfaces: the ESXi hosts (connected or not, powered on or not).
//   - Show: "show vms", "show vm NAME|ID" (everything about ONE virtual machine as one answer: its record, power state, guest
//     identity, guest network and VMware Tools), "show hosts", "show clusters", "show datacenters", "show datastores", "show networks",
//     "show folders", "show resourcepools", "show version" and "show health" (the appliance's health).
//   - APIGet: any read below /vcenter, /appliance, /cis, /content, /esx and /vstats.  Sessions, users, accounts, tokens, passwords,
//     certificates and keys, KMS, guest processes and files, and console tickets are refused.
//   - RawChange (rw keys only): POST, PUT, PATCH and DELETE below /vcenter, /cis and /content (power, hardware, tags, folders,
//     resource pools ...; power actions are POST /vcenter/vm/ID/power?action=start|stop|reset|suspend).  Deleting a virtual machine,
//     host, cluster, datacenter, datastore, folder, resource pool or network, or a disk, is refused, and so are deployment, restore,
//     certificates, guest operations and console tickets.  The appliance (network, time, services, shutdown, reboot, SSH) is read, not
//     changed.
//
// What an answer holds that is named like a secret is hidden (dnsHide, Redact).  The field names are those of VMware's API; "show vm"
// keeps the whole record, so a field a release names otherwise is still shown.

func init() { Register("vcenter", newVCenter) }

type vcenter struct {
	d      Device
	api    *apiClient
	user   string
	pass   string
	style  string // "", "api" or "rest" (forced); decided at the first sign-in when empty
	legacy bool

	mu   sync.Mutex
	sess string
}

var (
	vcRefRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._: -]{0,127}$`)
	vcIDRE    = regexp.MustCompile(`^[a-z-]{2,24}-[0-9]+$`)
	vcPathRE  = regexp.MustCompile(`^/[A-Za-z0-9._~%:-]+(/[A-Za-z0-9._~%:-]+)*$`)
	vcRootRE  = regexp.MustCompile(`^/(api|rest)(/|$)`)
	vcReadSeg = map[string]bool{"vcenter": true, "appliance": true, "cis": true, "content": true, "esx": true, "vstats": true}
	vcWriteSg = map[string]bool{"vcenter": true, "cis": true, "content": true}
	// parts of a path that are who may sign in, what they may do, keys, and a way into a guest or a console: never read or written
	vcDenied = []string{"session", "users", "user", "local-accounts", "accounts", "tokens", "token", "password", "passwords", "authentication", "sso", "certificate-management",
		"certificates", "vmca", "key-providers", "kms", "crypto-manager", "secrets", "processes", "filesystem", "tickets", "trusted-infrastructure", "credentials"}
	// written never: installing, restoring, and the appliance's own network, time and services
	vcNoWrite = []string{"deployment", "restore", "recovery", "backup", "namespace-management", "lcm", "update", "upgrade"}
	// resources whose DELETE (the resource itself, one level below the type) is refused
	vcNoDelete = map[string]bool{"vm": true, "host": true, "cluster": true, "datacenter": true, "datastore": true, "folder": true, "resource-pool": true, "network": true}
)

func newVCenter(d Device, c Credential) (Driver, error) {
	if c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("device %s: vCenter needs a Single Sign-On user name (user@vsphere.local) and a password", d.Name)
	}
	st := strings.ToLower(strings.TrimSpace(d.Options["api_style"]))
	switch st {
	case "", "auto":
		st = ""
	case "api", "rest":
	default:
		return nil, fmt.Errorf("device %s: option api_style is api (7.0 Update 2 and later), rest (older), or auto", d.Name)
	}
	api, err := newAPIClient(d, 443)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	return &vcenter{d: d, api: api, user: c.Username, pass: c.Password, style: st, legacy: st == "rest"}, nil
}

func (v *vcenter) root() string {
	if v.legacy {
		return "/rest"
	}
	return "/api"
}

// signIn creates the session: the new endpoint first, the old one when the new does not exist.
func (v *vcenter) signIn(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sess != "" {
		return v.sess, nil
	}
	basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(v.user+":"+v.pass))}}
	try := func(path string) (string, error) {
		b, err := v.api.do(context.WithoutCancel(ctx), http.MethodPost, path, nil, basic)
		if err != nil {
			return "", err
		}
		var x any
		if json.Unmarshal(b, &x) != nil {
			return "", errors.New("the answer is not JSON")
		}
		switch t := x.(type) {
		case string:
			return t, nil
		case map[string]any:
			return str(t["value"]), nil
		}
		return "", errors.New("the answer holds no session ID")
	}
	var id string
	var err error
	if v.style != "rest" {
		id, err = try("/api/session")
		var se *statusError
		if err != nil && v.style == "" && errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusMethodNotAllowed) {
			id, err = try("/rest/com/vmware/cis/session")
			v.legacy = err == nil
		}
	} else {
		id, err = try("/rest/com/vmware/cis/session")
	}
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Code == http.StatusUnauthorized {
			return "", errors.New("vCenter: sign-in refused (wrong user name or password; the user name is written user@vsphere.local)")
		}
		return "", fmt.Errorf("vCenter: sign-in failed: %w", err)
	}
	if id == "" {
		return "", errors.New("vCenter: sign-in failed: the answer holds no session ID")
	}
	v.sess = id
	return id, nil
}

// do sends one request below the API root with the session; a session that has expired (401) is renewed once.
func (v *vcenter) do(ctx context.Context, method, path string, body any, h http.Header) ([]byte, error) {
	for try := 0; ; try++ {
		id, err := v.signIn(ctx)
		if err != nil {
			return nil, err
		}
		hdr := http.Header{}
		for k, x := range h {
			hdr[k] = x
		}
		hdr.Set("vmware-api-session-id", id)
		b, err := v.api.do(ctx, method, v.root()+path, body, hdr)
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code == http.StatusUnauthorized && try == 0 {
			v.mu.Lock()
			v.sess = ""
			v.mu.Unlock()
			continue
		}
		return b, err
	}
}

// get reads one path below the API root; an old endpoint's {"value": ...} is taken off.
func (v *vcenter) get(ctx context.Context, path string) (any, error) {
	b, err := v.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var x any
	if err := json.Unmarshal(b, &x); err != nil {
		return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
	}
	if m, ok := x.(map[string]any); ok && v.legacy && len(m) == 1 {
		if val, ok := m["value"]; ok {
			return val, nil
		}
	}
	return x, nil
}

func (v *vcenter) Facts(ctx context.Context) (Facts, error) {
	if _, err := v.signIn(ctx); err != nil {
		return Facts{}, err
	}
	f := Facts{Hostname: v.d.Address, Vendor: "VMware", Model: "vCenter Server"}
	x, err := v.get(ctx, "/appliance/system/version")
	if err != nil {
		// the appliance service may be closed to this user: the sign-in worked, a read of the inventory proves it can read
		if _, err2 := v.get(ctx, "/vcenter/datacenter"); err2 != nil {
			return Facts{}, err2
		}
		return f, nil
	}
	if m, ok := x.(map[string]any); ok {
		f.OSVersion = strings.TrimSpace(str(m["version"]) + " build " + str(m["build"]))
		if p := str(m["product"]); p != "" {
			f.Model = p
		}
	}
	return f, nil
}

func (v *vcenter) hosts(ctx context.Context) ([]map[string]any, error) {
	x, err := v.get(ctx, "/vcenter/host")
	if err != nil {
		return nil, err
	}
	return rows(x), nil
}

func (v *vcenter) Interfaces(ctx context.Context) ([]Interface, error) {
	hs, err := v.hosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(hs))
	for _, h := range hs {
		i := Interface{Name: firstOf(str(h["name"]), str(h["host"])), Description: "ESXi host " + str(h["host"])}
		if c := str(h["connection_state"]); c != "" {
			i.OperUp = boolp(c == "CONNECTED")
			i.Description += ", " + strings.ToLower(c)
		}
		if p := str(h["power_state"]); p != "" {
			i.AdminUp = boolp(p == "POWERED_ON")
		}
		out = append(out, i)
	}
	return out, nil
}

func (v *vcenter) Neighbors(context.Context) ([]Neighbor, error) { return nil, ErrUnsupported }
func (v *vcenter) Config(context.Context) (string, error)        { return "", ErrUnsupported }

func (v *vcenter) Close(ctx context.Context) {
	v.mu.Lock()
	id := v.sess
	v.mu.Unlock()
	if id != "" {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		path := "/api/session"
		if v.legacy {
			path = "/rest/com/vmware/cis/session"
		}
		_, _ = v.api.do(c, http.MethodDelete, path, nil, http.Header{"vmware-api-session-id": {id}})
		cancel()
	}
	v.api.close()
}

const vcUsage = "show vms [state=POWERED_ON|POWERED_OFF|SUSPENDED] [search=TEXT] [limit=N] | vm NAME|ID | hosts | clusters | datacenters | datastores | networks | folders | resourcepools | version | health"

var vcLists = map[string]string{"hosts": "/vcenter/host", "clusters": "/vcenter/cluster", "datacenters": "/vcenter/datacenter", "datastores": "/vcenter/datastore",
	"networks": "/vcenter/network", "folders": "/vcenter/folder", "resourcepools": "/vcenter/resource-pool"}

var vcHealth = []string{"system", "load", "mem", "storage", "swap", "database-storage", "applmgmt", "softwarepackages"}

func (v *vcenter) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(vcUsage)
	}
	w := strings.ToLower(f[1])
	if p, ok := vcLists[w]; ok {
		if len(f) != 2 {
			return "", errors.New(vcUsage)
		}
		x, err := v.get(ctx, p)
		if err != nil {
			return "", err
		}
		rs := rows(x)
		return nsList(rs, len(rs), len(rs)+1, ""), nil
	}
	switch w {
	case "version":
		if len(f) != 2 {
			return "", errors.New(vcUsage)
		}
		x, err := v.get(ctx, "/appliance/system/version")
		if err != nil {
			return "", err
		}
		return dnsText(x), nil
	case "health":
		if len(f) != 2 {
			return "", errors.New(vcUsage)
		}
		out := map[string]any{}
		errs := map[string]string{}
		for _, h := range vcHealth {
			x, err := v.get(ctx, "/appliance/health/"+h)
			if err != nil {
				errs[h] = RedactText(err.Error())
				continue
			}
			out[h] = x
		}
		if len(out) == 0 && len(errs) > 0 {
			return "", fmt.Errorf("the appliance health could not be read: %s", errs["system"])
		}
		if len(errs) > 0 {
			out["errors"] = errs
		}
		return dnsText(out), nil
	case "vms":
		a, err := centArgs(f[2:], "state", "search", "limit")
		if err != nil {
			return "", err
		}
		q := url.Values{}
		if s := strings.ToUpper(a["state"]); s != "" {
			if s != "POWERED_ON" && s != "POWERED_OFF" && s != "SUSPENDED" {
				return "", errors.New("state: POWERED_ON, POWERED_OFF or SUSPENDED")
			}
			q.Set("power_states", s)
		}
		p := "/vcenter/vm"
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		x, err := v.get(ctx, p)
		if err != nil {
			return "", err
		}
		all := rows(x)
		var out []map[string]any
		for _, r := range all {
			if s := a["search"]; s != "" && !centContains(str(r["name"])+" "+str(r["vm"]), s) {
				continue
			}
			out = append(out, r)
		}
		return nsList(out, len(all), centLimit(a), ""), nil
	case "vm":
		ref := strings.Join(f[2:], " ")
		if ref == "" || !vcRefRE.MatchString(ref) {
			return "", errors.New("show vm NAME|ID: the virtual machine's name or its ID such as vm-12 (show vms lists them)")
		}
		all, err := v.vmAll(ctx, ref)
		if err != nil {
			return "", err
		}
		return dnsText(all), nil
	}
	return "", errors.New(vcUsage)
}

// findVM finds one virtual machine by ID or by name.
func (v *vcenter) findVM(ctx context.Context, ref string) (string, error) {
	if vcIDRE.MatchString(ref) {
		return ref, nil
	}
	x, err := v.get(ctx, "/vcenter/vm?"+url.Values{"names": {ref}}.Encode())
	if err != nil {
		return "", err
	}
	var ids []string
	for _, r := range rows(x) {
		if strings.EqualFold(str(r["name"]), ref) && str(r["vm"]) != "" {
			ids = append(ids, str(r["vm"]))
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no virtual machine %q (show vms lists them)", ref)
	case 1:
		return ids[0], nil
	}
	sort.Strings(ids)
	return "", fmt.Errorf("%d virtual machines are called %q (%s): give the ID", len(ids), ref, strings.Join(ids, ", "))
}

// vmAll answers everything vCenter holds about one virtual machine.  A part that cannot be read (no VMware Tools, no privilege) is
// named under "errors"; the rest is still answered.
func (v *vcenter) vmAll(ctx context.Context, ref string) (map[string]any, error) {
	id, err := v.findVM(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"id": id}
	errs := map[string]string{}
	part := func(key, path string) {
		x, err := v.get(ctx, "/vcenter/vm/"+id+path)
		if err != nil {
			errs[key] = RedactText(err.Error())
			return
		}
		out[key] = x
	}
	part("vm", "")
	if _, ok := out["vm"]; !ok {
		return nil, fmt.Errorf("virtual machine %s: %s", id, errs["vm"])
	}
	part("power", "/power")
	part("guest_identity", "/guest/identity")
	part("guest_network", "/guest/networking/interfaces")
	part("tools", "/tools")
	if len(errs) > 0 {
		out["errors"] = errs
	}
	return out, nil
}

// ---- reading through the API ----

// vcRel takes /api or /rest off a path that was given with it.
func vcRel(p string) string {
	if m := vcRootRE.FindString(p); m != "" {
		return "/" + p[len(m):]
	}
	return p
}

func (v *vcenter) APIGet(ctx context.Context, path string) (any, bool, error) {
	pp, qs, _ := strings.Cut(path, "?")
	pp = vcRel(pp)
	if !vcPathRE.MatchString(pp) || strings.Contains(pp, "..") || strings.Contains(pp, "//") {
		return nil, false, errors.New("path: /vcenter/vm, /vcenter/vm/vm-12/power, /appliance/system/version (see device_api_catalog)")
	}
	if !vcReadSeg[dnsSegs(pp)[0]] {
		return nil, false, errors.New("path: vCenter is read below /vcenter, /appliance, /cis, /content, /esx and /vstats")
	}
	if hasSeg(pp, vcDenied...) {
		return nil, false, errors.New("path: sessions, users, accounts, tokens, passwords, certificates and keys, KMS, guest processes and files, and console tickets are not read here")
	}
	enc, err := centQuery(qs)
	if err != nil {
		return nil, false, err
	}
	if enc != "" {
		pp += "?" + enc
	}
	x, err := v.get(ctx, pp)
	if err != nil {
		return nil, false, err
	}
	return obsScrub(Redact(dnsHide(x))), false, nil
}

func (v *vcenter) APICatalog(context.Context) (any, error) {
	ex := []string{"/vcenter/vm", "/vcenter/vm?names=web01", "/vcenter/vm/vm-12", "/vcenter/vm/vm-12/power", "/vcenter/vm/vm-12/hardware", "/vcenter/vm/vm-12/guest/identity",
		"/vcenter/vm/vm-12/guest/networking/interfaces", "/vcenter/vm/vm-12/tools", "/vcenter/host", "/vcenter/cluster", "/vcenter/datacenter", "/vcenter/datastore",
		"/vcenter/network", "/vcenter/folder", "/vcenter/resource-pool", "/appliance/system/version", "/appliance/health/system", "/appliance/networking",
		"/appliance/services", "/cis/tasks", "/content/library"}
	sort.Strings(ex)
	return map[string]any{
		"how": "Paths below /vcenter, /appliance, /cis, /content, /esx and /vstats (/api is added; an older vCenter is asked at /rest). Lists take filters such as " +
			"?names=, ?power_states=, ?clusters=. Sessions, users, accounts, tokens, passwords, certificates and keys, KMS, guest processes and files, and console tickets " +
			"are refused. Changes are device_change_raw below /vcenter, /cis and /content: POST /vcenter/vm/ID/power?action=start|stop|reset|suspend, PATCH hardware, " +
			"tags and so on; deleting a VM, host, cluster, datacenter, datastore, folder, resource pool, network or disk is refused.",
		"examples": ex,
		"tip":      "show vm NAME (device_show) answers everything about one virtual machine in one call; the full API is at https://developer.broadcom.com/xapis/vsphere-automation-api/latest/.",
	}, nil
}

// ---- changes ----

func vcGuard(method, p string) error {
	pp, _, _ := strings.Cut(p, "?")
	pp = vcRel(pp)
	if !vcPathRE.MatchString(pp) {
		return errors.New("path: /vcenter/vm/vm-12/power?action=start")
	}
	segs := dnsSegs(pp)
	if !vcWriteSg[segs[0]] {
		return errors.New("path: vCenter is changed below /vcenter, /cis and /content (the appliance is read only here)")
	}
	if hasSeg(pp, vcDenied...) || hasSeg(pp, vcNoWrite...) {
		return errors.New("path: sessions, users, accounts, tokens, certificates and keys, KMS, guest processes and files, console tickets, deployment, restore and updates are not changed here")
	}
	if method == http.MethodDelete {
		if segs[0] == "vcenter" && len(segs) >= 2 && vcNoDelete[segs[1]] && len(segs) <= 3 {
			return errors.New("path: a virtual machine, host, cluster, datacenter, datastore, folder, resource pool or network is not deleted here: use vCenter itself")
		}
		if hasSeg(pp, "disk", "disks") {
			return errors.New("path: a disk is not removed here: use vCenter itself")
		}
	}
	return nil
}

// RawChange: Method POST, PUT, PATCH or DELETE, Path below /vcenter, /cis or /content (an action is a query: ?action=start), Body JSON.
func (v *vcenter) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	r.Path = vcRel(r.Path)
	if _, err := v.get(ctx, "/vcenter/datacenter"); err != nil {
		return RawResult{DryRun: dry}, fmt.Errorf("vCenter did not answer a read (nothing was changed): %w", err)
	}
	id, _ := v.signIn(ctx)
	h := jsonHdr()
	h.Set("vmware-api-session-id", id)
	return restRaw(ctx, restSpec{
		api: v.api, hdr: h, auth: http.Header{"vmware-api-session-id": {id}, "Accept": {"application/json"}}, json: true,
		wire:  func(p string) string { return v.root() + p },
		guard: vcGuard,
		alive: func(ctx context.Context) error {
			_, err := v.get(ctx, "/vcenter/datacenter")
			return err
		},
	}, r, dry)
}
