package device

import (
	"context"
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

// What Proxmox Backup Server (pbs.go) and Proxmox Datacenter Manager (pdm.go) have in common with Proxmox VE: the REST API at
// https://HOST:PORT/api2/json, every answer {"data": ...}, a login that is an API token or a ticket.  The two differ from VE in
// the header of a token ("PBSAPIToken=USER@REALM!ID:SECRET", a colon before the secret, not an equals sign) and in the port.
//
// A token is given as the whole string (user@realm!id:secret) in the credential's token, or as user@realm!id in its user name and the
// secret in its token.  Or a user name with its realm and a password: the driver asks for a ticket (POST /access/ticket), sends it as
// a cookie with the CSRF token on writes, and asks again when it is refused (a realm with two-factor login needs a token).
//
// The paths and fields come from Proxmox's API viewers; none was tried against a real server.

// pxSpec is what one product says about itself.
type pxSpec struct {
	name      string // "Proxmox Backup Server"
	short     string // "PBS", for messages
	platform  string
	prefix    string // the token header's word
	cookie    string // the ticket cookie
	show      map[string]string
	denyRead  map[string]bool
	denyWrite map[string]string
	guard     func(method string, segs []string) error // what else a change must not be
	catalog   string
	examples  []string
}

type pxmx struct {
	spec     pxSpec
	d        Device
	api      *apiClient
	tokenHdr string
	user     string
	pass     string
	mu       sync.Mutex
	ticket   string
	csrf     string
	got      time.Time
}

const pxBase = "/api2/json"

var (
	pxSegRE   = regexp.MustCompile(`^[A-Za-z0-9_.:@!%=,+-]{1,200}$`)
	pxNameRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
	pxTaskNow = time.Millisecond * 2000 // how often a task is looked at; a variable so tests are quick
)

func newPxmx(spec pxSpec, d Device, c Credential) (*pxmx, error) {
	p := &pxmx{spec: spec, d: d}
	switch {
	case strings.Contains(c.Token, "!") && strings.Contains(c.Token, ":"):
		p.tokenHdr = spec.prefix + "=" + c.Token
	case strings.Contains(c.Username, "!") && c.Token != "":
		p.tokenHdr = spec.prefix + "=" + c.Username + ":" + c.Token
	case c.Username != "" && c.Password != "":
		p.user, p.pass = c.Username, c.Password
	default:
		return nil, fmt.Errorf("device %s: %s needs an API token (user@realm!id:secret, as the token, or user@realm!id as the user name and the secret as the token), or a user name with its realm and a password", d.Name, spec.name)
	}
	api, err := newAPIClient(d, DefaultPort(spec.platform))
	if err != nil {
		return nil, err
	}
	api.hdr.Set("User-Agent", "netdir")
	p.api = api
	return p, nil
}

func (p *pxmx) login(ctx context.Context, force bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ticket != "" && !force && time.Since(p.got) < 90*time.Minute {
		return nil
	}
	form := url.Values{"username": {p.user}, "password": {p.pass}}
	b, err := p.api.do(ctx, http.MethodPost, pxBase+"/access/ticket", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	var t struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &t) != nil || t.Data.Ticket == "" {
		return errors.New("login: the answer holds no ticket (an account with a second factor needs an API token)")
	}
	p.ticket, p.csrf, p.got = t.Data.Ticket, t.Data.CSRF, time.Now()
	return nil
}

func (p *pxmx) auth(ctx context.Context, write bool) (http.Header, error) {
	if p.tokenHdr != "" {
		return http.Header{"Authorization": {p.tokenHdr}}, nil
	}
	if err := p.login(ctx, false); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := http.Header{"Cookie": {p.spec.cookie + "=" + url.QueryEscape(p.ticket)}}
	if write {
		h.Set("CSRFPreventionToken", p.csrf)
	}
	return h, nil
}

// get reads a path below /api2/json and returns what is in "data"; a refused ticket is renewed once.
func (p *pxmx) get(ctx context.Context, path string) (any, error) {
	for renewed := false; ; renewed = true {
		h, err := p.auth(ctx, false)
		if err != nil {
			return nil, err
		}
		b, err := p.api.do(ctx, http.MethodGet, pxBase+path, nil, h)
		var se *statusError
		if err != nil && p.tokenHdr == "" && errors.As(err, &se) && se.Code == http.StatusUnauthorized && !renewed {
			if err := p.login(ctx, true); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var v struct {
			Data any `json:"data"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("GET %s: the answer is not JSON: %v", path, err)
		}
		return v.Data, nil
	}
}

func (p *pxmx) showNames() string {
	var n []string
	for k := range p.spec.show {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// show answers "show NAME [store=N] [remote=N]": a read from the table of the product, the secrets hidden.
func (p *pxmx) show(ctx context.Context, cmd string) (string, error) {
	usage := fmt.Errorf("show NAME [store=NAME] [remote=NAME], e.g. show %s; names: %s", firstKey(p.spec.show), p.showNames())
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", usage
	}
	tpl, ok := p.spec.show[strings.ToLower(f[1])]
	if !ok {
		return "", fmt.Errorf("show %s: not a read the %s driver has; names: %s", f[1], p.spec.short, p.showNames())
	}
	vals := map[string]string{}
	for _, kv := range f[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || (k != "store" && k != "remote") || !pxNameRE.MatchString(v) {
			return "", fmt.Errorf("%q: use store=NAME or remote=NAME", kv)
		}
		vals[k] = v
	}
	for _, k := range []string{"store", "remote"} {
		if strings.Contains(tpl, "{"+k+"}") {
			if vals[k] == "" {
				return "", fmt.Errorf("show %s needs %s=NAME", f[1], k)
			}
			tpl = strings.ReplaceAll(tpl, "{"+k+"}", url.PathEscape(vals[k]))
		}
	}
	v, err := p.get(ctx, tpl)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

func firstKey(m map[string]string) string {
	var n []string
	for k := range m {
		n = append(n, k)
	}
	sort.Strings(n)
	if len(n) == 0 {
		return ""
	}
	return n[0]
}

// pxNameParents are the segments after which the next one is a name or an id somebody chose (a datastore, a remote, a job, a node, a
// task), not a part of the API: a datastore called "backup" is a datastore, and only the /backup of the API is the backup protocol.
var pxNameParents = map[string]bool{"datastore": true, "remote": true, "remotes": true, "sync": true, "verify": true, "prune": true, "tasks": true,
	"nodes": true, "namespace": true, "traffic-control": true, "qemu": true, "lxc": true, "storage": true, "pools": true}

func pxIsName(segs []string, i int) bool { return i > 0 && pxNameParents[strings.ToLower(segs[i-1])] }

// read checks a path a caller wants read: below /api2/json, plain segments, none of those that hold accounts, consoles, keys or files.
func (p *pxmx) read(path string) (string, error) {
	rp := strings.TrimPrefix(path, pxBase)
	pp, q, _ := strings.Cut(rp, "?")
	if _, err := url.ParseQuery(q); err != nil {
		return "", errors.New("path: the query is not valid")
	}
	if !strings.HasPrefix(pp, "/") {
		return "", errors.New("path: a path that starts with /")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if len(segs) > 10 || segs[0] == "" {
		return "", errors.New("path: see device_api_catalog")
	}
	for i, s := range segs {
		if !pxSegRE.MatchString(s) {
			return "", fmt.Errorf("path: %q is not a path segment", s)
		}
		if p.spec.denyRead[strings.ToLower(s)] && !pxIsName(segs, i) {
			return "", fmt.Errorf("path: %q holds accounts, consoles, keys or files and is not read here", s)
		}
	}
	return rp, nil
}

func (p *pxmx) apiGet(ctx context.Context, path string) (any, bool, error) {
	rp, err := p.read(path)
	if err != nil {
		return nil, false, err
	}
	v, err := p.get(ctx, rp)
	if err != nil {
		return nil, false, err
	}
	return Redact(v), false, nil
}

func (p *pxmx) apiCatalog() (any, error) {
	return map[string]any{"how": p.spec.catalog, "examples": p.spec.examples}, nil
}

// rawGuard refuses what could lock the person out or destroy data in one call.
func (p *pxmx) rawGuard(method, path string) error {
	pp, q, _ := strings.Cut(path, "?")
	if q != "" {
		return errors.New("path: no query on a change (the parameters go in the JSON body)")
	}
	segs := strings.Split(strings.Trim(pp, "/"), "/")
	if segs[0] == "" {
		return errors.New("path: a path that starts with /")
	}
	for i, s := range segs {
		if !pxSegRE.MatchString(s) {
			return fmt.Errorf("path: %q is not a path segment", s)
		}
		if why, no := p.spec.denyWrite[strings.ToLower(s)]; no && !pxIsName(segs, i) {
			return fmt.Errorf("path: %q is not changed here (%s)", s, why)
		}
	}
	// /nodes/N/status: restarting or shutting down the machine; /nodes/N/services/S/stop: a service
	for i, s := range segs {
		if s == "nodes" && method == http.MethodPost && len(segs) == i+3 && strings.EqualFold(segs[i+2], "status") {
			return errors.New("path: restarting or shutting down the machine is not done here")
		}
		if s == "services" && method == http.MethodPost && len(segs) == i+3 {
			switch strings.ToLower(segs[i+2]) {
			case "stop", "restart", "reload":
				return errors.New("path: a service is not stopped or restarted here")
			}
		}
	}
	if p.spec.guard != nil {
		return p.spec.guard(method, segs)
	}
	return nil
}

// bodyCheck refuses a body that restores or purges, or asks for what is gone at the other end to be removed here.
func pxBodyCheck(r Raw) error {
	if strings.TrimSpace(r.Body) == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(r.Body), &m) != nil {
		return errors.New("body: a JSON object")
	}
	for k, v := range m {
		switch strings.ToLower(k) {
		case "archive":
			return errors.New("body: restoring a backup (archive) is not done here")
		case "purge", "destroy-unreferenced-disks", "remove-vanished", "destroy-data":
			if b, _ := v.(bool); b || fmt.Sprint(v) == "1" {
				return fmt.Errorf("body: %q removes data and is not sent here", k)
			}
		}
	}
	return nil
}

func (p *pxmx) rawChange(ctx context.Context, r Raw, dry bool, waitTasks bool) (RawResult, error) {
	r.Path = strings.TrimPrefix(r.Path, pxBase)
	if err := pxBodyCheck(r); err != nil {
		return RawResult{DryRun: dry}, err
	}
	h, err := p.auth(ctx, true)
	if err != nil {
		return RawResult{DryRun: dry}, err
	}
	auth := h.Clone()
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	res, err := restRaw(ctx, restSpec{
		api: p.api, hdr: h, auth: auth, json: true,
		wire:    func(path string) string { return pxBase + path },
		guard:   p.rawGuard,
		restore: nil,
		alive:   func(ctx context.Context) error { _, err := p.get(ctx, "/version"); return err },
	}, r, dry)
	if err != nil || !res.Applied {
		return res, err
	}
	if waitTasks {
		return p.waitTask(ctx, res)
	}
	return p.noteTask(res), nil
}

// upidOf is the task id a change answered with, if it started one.
func upidOf(answer string) (upid string, parts []string) {
	var a struct {
		Data any `json:"data"`
	}
	if json.Unmarshal([]byte(answer), &a) != nil {
		return "", nil
	}
	upid, _ = a.Data.(string)
	if i := strings.Index(upid, "UPID:"); i >= 0 {
		upid = upid[i:]
	}
	parts = strings.Split(upid, ":")
	if !strings.HasPrefix(upid, "UPID:") || len(parts) < 7 {
		return "", nil
	}
	return upid, parts
}

func (p *pxmx) noteTask(res RawResult) RawResult {
	if upid, _ := upidOf(res.Answer); upid != "" {
		res.Note = strings.TrimSpace(res.Note + " A task was started (" + upid + "); its end is not waited for: read it with show remote-tasks or show tasks.")
	}
	return res
}

// waitTask: a change that started a task answers with its UPID; wait for the task to end, and say how.
func (p *pxmx) waitTask(ctx context.Context, res RawResult) (RawResult, error) {
	upid, parts := upidOf(res.Answer)
	if upid == "" {
		return res, nil
	}
	base := "/nodes/localhost/tasks/" + url.PathEscape(upid)
	deadline := time.Now().Add(10 * time.Minute)
	for {
		v, err := p.get(ctx, base+"/status")
		if err != nil {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " was started; its end could not be read: " + err.Error())
			return res, nil
		}
		m, _ := v.(map[string]any)
		if str(m["status"]) == "stopped" {
			exit := str(m["exitstatus"])
			res.Answer = fmt.Sprintf("task %s ended: %s", parts[5], firstOf(exit, "unknown"))
			if exit == "OK" || strings.HasPrefix(exit, "WARNINGS") {
				return res, nil
			}
			lines := ""
			if lv, err := p.get(ctx, base+"/log?limit=20"); err == nil {
				for _, l := range rows(lv) {
					lines += str(l["t"]) + "\n"
				}
			}
			return res, fmt.Errorf("the task failed: %s\n%s", exit, rawTrunc([]byte(lines)))
		}
		if time.Now().After(deadline) {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " is still running.")
			return res, nil
		}
		if err := sleepCtx(ctx, pxTaskNow); err != nil {
			res.Note = strings.TrimSpace(res.Note + " The task " + upid + " was started; waiting for it was cut short.")
			return res, nil
		}
	}
}

// interfaces are the network interfaces of the machine, as the node network list gives them.
func (p *pxmx) interfaces(ctx context.Context) ([]Interface, error) {
	v, err := p.get(ctx, "/nodes/localhost/network")
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, i := range rows(v) {
		x := Interface{Name: firstOf(str(i["iface"]), str(i["name"])), Description: strings.TrimSpace(str(i["type"]) + " " + str(i["comments"]))}
		if _, ok := i["active"]; ok {
			up := num(i["active"]) == 1
			x.AdminUp, x.OperUp = &up, &up
		}
		for _, a := range []string{"cidr", "cidr6"} {
			if s := str(i[a]); s != "" {
				x.Addresses = append(x.Addresses, s)
			}
		}
		out = append(out, x)
	}
	return out, nil
}

func (p *pxmx) uptime(ctx context.Context) int64 {
	v, err := p.get(ctx, "/nodes/localhost/status")
	if err != nil {
		return 0
	}
	m, _ := v.(map[string]any)
	return num(m["uptime"])
}
