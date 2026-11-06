package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Packet capture on the platforms that can do it.  Each one runs the capture into a file or a buffer of its own, fetches it,
// and removes it again, also when the capture failed (cleanup uses a context of its own, so a cancelled request still cleans up).
//
//	dnsdir, ntpdir  the director's own timed capture (POST /api/capture/job, then GET until done), through its MCP key
//	eos             tcpdump in the switch's shell through eAPI ("bash"): only traffic to and from the switch's CPU is seen
//	bigip           tcpdump through iControl util/bash; interface 0.0 is every VLAN
//
// Not done: PAN-OS and FortiOS (their captures are global debug state on the box and have steps that cannot be tried here),
// NX-OS (ethanalyzer: CPU traffic only, text), IOS-XE (the file stays on the switch), AOS-CX, Technitium, Infoblox.

func cleanupCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// ---- DNS Director and NTP Director ----

func (m *director) Capture(ctx context.Context, r CaptureReq) (CaptureResult, error) {
	var res CaptureResult
	r, err := r.check()
	if err != nil {
		return res, err
	}
	if r.Interface == "" {
		if r.Interface, err = m.captureIface(ctx); err != nil {
			return res, err
		}
	}
	id, err := randHex()
	if err != nil {
		return res, err
	}
	id = "netdir" + id
	if _, err := m.call(ctx, "api_request", map[string]any{"method": http.MethodPost, "path": "/api/capture/job",
		"body": map[string]any{"id": id, "iface": r.Interface, "filter": r.Filter, "seconds": r.Seconds}}); err != nil {
		return res, fmt.Errorf("start the capture: %w", err)
	}
	if err := sleepCtx(ctx, time.Duration(r.Seconds)*time.Second+500*time.Millisecond); err != nil {
		return res, err
	}
	var st struct {
		Done  bool   `json:"done"`
		Error string `json:"error"`
		Pcap  []byte `json:"pcap"`
	}
	for i := 0; ; i++ {
		v, err := m.call(ctx, "api_get", map[string]any{"path": "/api/capture/job?id=" + id})
		if err != nil {
			return res, fmt.Errorf("fetch the capture: %w", err)
		}
		st.Done, st.Error, st.Pcap = false, "", nil
		b, _ := json.Marshal(v)
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(b, &env) == nil && len(env.Data) > 0 {
			b = env.Data
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return res, fmt.Errorf("fetch the capture: unexpected answer: %v", err)
		}
		if st.Error != "" {
			return res, fmt.Errorf("the director's capture failed: %s", rawTrunc([]byte(st.Error)))
		}
		if st.Done {
			break
		}
		if i >= 10 {
			return res, errors.New("the director's capture did not finish")
		}
		if err := sleepCtx(ctx, time.Second); err != nil {
			return res, err
		}
	}
	res, err = summarizePcap(st.Pcap)
	res.Interface, res.Filter, res.Seconds = r.Interface, r.Filter, r.Seconds
	if err == nil && len(st.Pcap) >= capMaxFile {
		res.Note = strings.TrimSpace(res.Note + " the director's file may hold only the newest packets")
	}
	return res, err
}

// captureIface picks the interface the director's gateways use, else the first one that is up and not the loopback.
func (m *director) captureIface(ctx context.Context) (string, error) {
	v, err := m.call(ctx, "api_get", map[string]any{"path": "/api/capture/interfaces"})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(v)
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(b, &out) == nil && len(out.Data) > 0 {
		b = out.Data
	}
	var d struct {
		Interfaces []struct {
			Name string `json:"name"`
			Up   bool   `json:"up"`
		} `json:"interfaces"`
		Gateway []string `json:"gateway"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", fmt.Errorf("interfaces: unexpected answer: %v", err)
	}
	for _, g := range d.Gateway {
		if capIfaceRE.MatchString(g) {
			return g, nil
		}
	}
	for _, i := range d.Interfaces {
		if i.Up && i.Name != "lo" && capIfaceRE.MatchString(i.Name) {
			return i.Name, nil
		}
	}
	return "", errors.New("interface: say which one (the director lists none that is up)")
}

// ---- Arista EOS ----

var eosFrontRE = regexp.MustCompile(`^(?i)(ethernet|management)([0-9]+)(?:/([0-9]+))?$`)

// eosKernelIf names an interface the way the switch's Linux does: Ethernet3 is et3, Ethernet3/1 is et3_1, Management1 is ma1.
func eosKernelIf(n string) string {
	m := eosFrontRE.FindStringSubmatch(n)
	if m == nil {
		return n
	}
	p := "et"
	if strings.EqualFold(m[1], "management") {
		p = "ma"
	}
	if m[3] != "" {
		return p + m[2] + "_" + m[3]
	}
	return p + m[2]
}

// eosBash runs one shell command through eAPI and returns what it printed.
func (e *eos) eosBash(ctx context.Context, cmd string) (string, error) {
	a, err := e.post(ctx, []string{"bash " + cmd}, "text")
	if err != nil {
		return "", err
	}
	if len(a.Result) == 0 {
		return "", errors.New("eAPI answered nothing")
	}
	m, _ := a.Result[0].(map[string]any)
	return str(m["output"]), nil
}

func (e *eos) Capture(ctx context.Context, r CaptureReq) (CaptureResult, error) {
	var res CaptureResult
	r, err := r.check()
	if err != nil {
		return res, err
	}
	if r.Interface == "" {
		return res, errors.New("interface: say which one (Ethernet1, Management1, or the Linux name such as et1, ma1, any)")
	}
	iface := eosKernelIf(r.Interface)
	id, err := randHex()
	if err != nil {
		return res, err
	}
	file := "/tmp/netdir-cap-" + id + ".pcap"
	defer func() {
		c, cancel := cleanupCtx()
		defer cancel()
		_, _ = e.eosBash(c, "rm -f "+file)
	}()
	out, err := e.eosBash(ctx, "sudo "+tcpdumpCmd(iface, r.Filter, r.Seconds, r.Packets, file))
	if err != nil {
		return res, fmt.Errorf("tcpdump: %w", err)
	}
	b64, err := e.eosBash(ctx, "base64 -w0 "+file)
	if err != nil {
		return res, fmt.Errorf("fetch the capture: %w", err)
	}
	raw, err := unB64(b64)
	if err != nil {
		return res, fmt.Errorf("%w [tcpdump said: %s]", err, rawTrunc([]byte(out)))
	}
	res, err = summarizePcap(raw)
	if err != nil {
		return res, fmt.Errorf("%w [tcpdump said: %s]", err, rawTrunc([]byte(out)))
	}
	res.Interface, res.Filter, res.Seconds = iface, r.Filter, r.Seconds
	res.Note = strings.TrimSpace(res.Note + " The switch's Linux sees only what goes to or from its CPU (control plane and management traffic), not what is switched in hardware.")
	return res, nil
}

// ---- F5 BIG-IP ----

func (b *bigip) bash(ctx context.Context, cmd string) (string, error) {
	body := map[string]any{"command": "run", "utilCmdArgs": `-c "` + cmd + `"`}
	raw, err := b.api.do(ctx, http.MethodPost, "/mgmt/tm/util/bash", body, jsonHdr())
	if err != nil {
		return "", err
	}
	var m struct {
		Result string `json:"commandResult"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("util/bash: the answer is not JSON: %v", err)
	}
	return m.Result, nil
}

func (b *bigip) Capture(ctx context.Context, r CaptureReq) (CaptureResult, error) {
	var res CaptureResult
	r, err := r.check()
	if err != nil {
		return res, err
	}
	if r.Interface == "" {
		r.Interface = "0.0" // every VLAN
	}
	id, err := randHex()
	if err != nil {
		return res, err
	}
	file := "/var/tmp/netdir-cap-" + id + ".pcap"
	defer func() {
		c, cancel := cleanupCtx()
		defer cancel()
		_, _ = b.bash(c, "rm -f "+file)
	}()
	out, err := b.bash(ctx, tcpdumpCmd(r.Interface, r.Filter, r.Seconds, r.Packets, file))
	if err != nil {
		return res, fmt.Errorf("tcpdump: %w", err)
	}
	b64, err := b.bash(ctx, "base64 -w0 "+file)
	if err != nil {
		return res, fmt.Errorf("fetch the capture: %w", err)
	}
	raw, err := unB64(b64)
	if err != nil {
		return res, fmt.Errorf("%w [tcpdump said: %s]", err, rawTrunc([]byte(out)))
	}
	res, err = summarizePcap(raw)
	if err != nil {
		return res, fmt.Errorf("%w [tcpdump said: %s]", err, rawTrunc([]byte(out)))
	}
	res.Interface, res.Filter, res.Seconds = r.Interface, r.Filter, r.Seconds
	res.Note = strings.TrimSpace(res.Note + " Interface 0.0 is every VLAN.")
	return res, nil
}
