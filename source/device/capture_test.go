package device

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// testPcap is a little-endian microsecond .pcap of Ethernet frames: 3 DNS queries 10.0.0.5 > 10.0.0.53, one TCP SYN, one ARP.
func testPcap() []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[20:], 1)
	eth := func(et uint16, payload []byte) []byte {
		f := make([]byte, 14, 14+len(payload))
		copy(f, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
		binary.BigEndian.PutUint16(f[12:], et)
		return append(f, payload...)
	}
	ip4 := func(proto byte, src, dst string, l4 []byte) []byte {
		h := make([]byte, 20)
		h[0] = 0x45
		h[9] = proto
		copy(h[12:], net.ParseIP(src).To4())
		copy(h[16:], net.ParseIP(dst).To4())
		return append(h, l4...)
	}
	udp := func(sp, dp uint16) []byte {
		u := make([]byte, 8)
		binary.BigEndian.PutUint16(u, sp)
		binary.BigEndian.PutUint16(u[2:], dp)
		return u
	}
	tcp := func(sp, dp uint16, flags byte) []byte {
		u := make([]byte, 20)
		binary.BigEndian.PutUint16(u, sp)
		binary.BigEndian.PutUint16(u[2:], dp)
		u[13] = flags
		return u
	}
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[6:], 1)
	copy(arp[14:], net.ParseIP("10.0.0.1").To4())
	copy(arp[24:], net.ParseIP("10.0.0.2").To4())
	frames := [][]byte{
		eth(0x0800, ip4(17, "10.0.0.5", "10.0.0.53", udp(40001, 53))),
		eth(0x0800, ip4(17, "10.0.0.5", "10.0.0.53", udp(40002, 53))),
		eth(0x0800, ip4(17, "10.0.0.5", "10.0.0.53", udp(40003, 53))),
		eth(0x0800, ip4(6, "10.0.0.7", "10.0.0.8", tcp(5555, 443, 0x02))),
		eth(0x0806, arp),
	}
	for i, f := range frames {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint32(r, 1700000000)
		binary.LittleEndian.PutUint32(r[4:], uint32(i*1000))
		binary.LittleEndian.PutUint32(r[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(r[12:], uint32(len(f)))
		b = append(append(b, r...), f...)
	}
	return b
}

func TestSummarizePcap(t *testing.T) {
	r, err := summarizePcap(testPcap())
	if err != nil {
		t.Fatal(err)
	}
	if r.Count != 5 || len(r.Listed) != 5 {
		t.Fatalf("count %d listed %d", r.Count, len(r.Listed))
	}
	if !strings.Contains(r.Listed[0], "UDP 10.0.0.5.40001 > 10.0.0.53.53") || !strings.HasPrefix(r.Listed[0], "+0.000000 ") {
		t.Errorf("first line %q", r.Listed[0])
	}
	if !strings.Contains(r.Listed[1], "+0.001000") {
		t.Errorf("second line %q", r.Listed[1])
	}
	if !strings.Contains(r.Listed[3], "TCP 10.0.0.7.5555 > 10.0.0.8.443 [S]") {
		t.Errorf("tcp line %q", r.Listed[3])
	}
	if !strings.Contains(r.Listed[4], "ARP who-has 10.0.0.2 tell 10.0.0.1") {
		t.Errorf("arp line %q", r.Listed[4])
	}
	if r.Protocols[0].Name != "DNS" || r.Protocols[0].Packets != 3 {
		t.Errorf("protocols %+v", r.Protocols)
	}
	if r.Talkers[0].Name != "10.0.0.5 > 10.0.0.53" || r.Talkers[0].Packets != 3 {
		t.Errorf("talkers %+v", r.Talkers)
	}
	// a cut-off last record is dropped, not an error
	if r, err := summarizePcap(testPcap()[:len(testPcap())-5]); err != nil || r.Count != 4 {
		t.Errorf("cut file: %v %d", err, r.Count)
	}
	for _, bad := range [][]byte{nil, []byte("nope nope nope nope nope nope"), make([]byte, 30)} {
		if _, err := summarizePcap(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCaptureCheck(t *testing.T) {
	r, err := CaptureReq{}.check()
	if err != nil || r.Seconds != capDefaultSeconds || r.Packets != capDefaultPackets {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	for _, bad := range []CaptureReq{
		{Seconds: 31}, {Seconds: -1}, {Packets: 2001}, {Packets: -3},
		{Filter: "port 53; reboot"}, {Filter: "host 'x'"}, {Filter: "a`b`"}, {Filter: "$(id)"}, {Filter: "port 53 | cat"},
		{Interface: "eth0; id"}, {Interface: "et 1"}, {Interface: strings.Repeat("a", 41)}, {Filter: strings.Repeat("a", 201)},
	} {
		if _, err := bad.check(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	for _, ok := range []CaptureReq{{Filter: "host 10.0.0.5 and (port 53 or port 123)"}, {Interface: "0.0:nnn"}, {Interface: "et1_1"}, {Filter: "ip6 and not arp"}} {
		if _, err := ok.check(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	if eosKernelIf("Ethernet3/1") != "et3_1" || eosKernelIf("Management1") != "ma1" || eosKernelIf("ethernet12") != "et12" || eosKernelIf("any") != "any" {
		t.Error("eosKernelIf")
	}
}

// fakeShell keeps the files a stub switch's shell writes and answers the three commands a capture runs.
type fakeShell struct {
	mu    sync.Mutex
	files map[string][]byte
	cmds  []string
	fail  bool // tcpdump writes nothing (the interface does not exist)
}

func (s *fakeShell) run(t *testing.T, cmd string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = append(s.cmds, cmd)
	f := strings.Fields(cmd)
	switch {
	case strings.Contains(cmd, "tcpdump "):
		for i, w := range f {
			if w == "-w" {
				if !s.fail {
					s.files[f[i+1]] = testPcap()
				}
			}
		}
		if s.fail {
			return "tcpdump: nosuch0: No such device exists"
		}
		return "5 packets captured"
	case strings.HasPrefix(cmd, "base64 -w0 "):
		b, ok := s.files[f[2]]
		if !ok {
			return "base64: " + f[2] + ": No such file or directory"
		}
		return base64.StdEncoding.EncodeToString(b)
	case strings.HasPrefix(cmd, "rm -f "):
		delete(s.files, f[2])
		return ""
	}
	t.Errorf("unexpected shell command %q", cmd)
	return ""
}

func eosCapStub(t *testing.T, sh *fakeShell) Device {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(401)
			return
		}
		var req struct {
			ID     string `json:"id"`
			Params struct {
				Cmds   []string `json:"cmds"`
				Format string   `json:"format"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/command-api" || len(req.Params.Cmds) != 1 || !strings.HasPrefix(req.Params.Cmds[0], "bash ") || req.Params.Format != "text" {
			t.Errorf("unexpected eAPI request %s %+v", r.URL, req)
		}
		out := sh.run(t, strings.TrimPrefix(strings.TrimPrefix(req.Params.Cmds[0], "bash "), "sudo "))
		_ = json.NewEncoder(w).Encode(J{"jsonrpc": "2.0", "id": req.ID, "result": []any{J{"output": out + "\n"}}})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	return Device{Name: "sw1", Platform: "eos", Address: host, Port: pn, Insecure: true}
}

func TestEOSCapture(t *testing.T) {
	sh := &fakeShell{files: map[string][]byte{}}
	d := eosCapStub(t, sh)
	drv, err := Open(d, Credential{Name: "c", Username: "admin", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := drv.(Capturer)
	if !ok {
		t.Fatal("eos is not a Capturer")
	}
	res, err := c.Capture(context.Background(), CaptureReq{Interface: "Ethernet3/1", Filter: "host 10.0.0.5 and port 53", Seconds: 3, Packets: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 5 || res.Interface != "et3_1" || res.Seconds != 3 || !strings.Contains(res.Note, "CPU") {
		t.Errorf("%+v", res)
	}
	var dump string
	for _, c := range sh.cmds {
		if strings.Contains(c, "tcpdump") {
			dump = c
		}
	}
	for _, want := range []string{"timeout 3 tcpdump -n -s 96 -i et3_1 -c 100 -w /tmp/netdir-cap-", "'host 10.0.0.5 and port 53'"} {
		if !strings.Contains(dump, want) {
			t.Errorf("tcpdump command %q lacks %q", dump, want)
		}
	}
	if len(sh.files) != 0 {
		t.Errorf("the capture file was left on the switch: %v", sh.files)
	}
	// a capture that wrote nothing: a clear error with what tcpdump said, and no file left
	sh.fail = true
	if _, err := c.Capture(context.Background(), CaptureReq{Interface: "nosuch0"}); err == nil || !strings.Contains(err.Error(), "No such device") {
		t.Errorf("failed capture: %v", err)
	}
	if len(sh.files) != 0 {
		t.Errorf("left files: %v", sh.files)
	}
	// nothing reaches the switch for a bad request
	n := len(sh.cmds)
	for _, bad := range []CaptureReq{{Interface: "et1", Filter: "port 1; reload"}, {}, {Interface: "et1", Seconds: 99}} {
		if _, err := c.Capture(context.Background(), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if len(sh.cmds) != n {
		t.Errorf("a refused request sent commands: %v", sh.cmds[n:])
	}
}

func TestBigIPCapture(t *testing.T) {
	sh := &fakeShell{files: map[string][]byte{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "s3cret" {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var q struct {
			Command string `json:"command"`
			Args    string `json:"utilCmdArgs"`
		}
		_ = json.Unmarshal(b, &q)
		if r.Method != http.MethodPost || r.URL.Path != "/mgmt/tm/util/bash" || q.Command != "run" || !strings.HasPrefix(q.Args, `-c "`) || !strings.HasSuffix(q.Args, `"`) {
			t.Errorf("unexpected %s %s %s", r.Method, r.URL, b)
		}
		out := sh.run(t, q.Args[4:len(q.Args)-1])
		_ = json.NewEncoder(w).Encode(J{"kind": "tm:util:bash:runstate", "commandResult": out})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	drv, err := Open(Device{Name: "ltm1", Platform: "bigip", Address: host, Port: pn, Insecure: true}, Credential{Name: "c", Username: "admin", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := drv.(Capturer).Capture(context.Background(), CaptureReq{Filter: "port 443"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 5 || res.Interface != "0.0" || res.Seconds != capDefaultSeconds {
		t.Errorf("%+v", res)
	}
	var dump string
	for _, c := range sh.cmds {
		if strings.Contains(c, "tcpdump") {
			dump = c
		}
	}
	if !strings.Contains(dump, "tcpdump -n -s 96 -i 0.0 -c 500 -w /var/tmp/netdir-cap-") || !strings.Contains(dump, "'port 443'") {
		t.Errorf("tcpdump command %q", dump)
	}
	if len(sh.files) != 0 {
		t.Errorf("left files: %v", sh.files)
	}
}

func TestDirectorCapture(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	polls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != "RWKEY" {
			w.WriteHeader(401)
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name string `json:"name"`
				Args struct {
					Method string          `json:"method"`
					Path   string          `json:"path"`
					Body   json.RawMessage `json:"body"`
				} `json:"arguments"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &q)
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, q.Params.Name+" "+q.Params.Args.Method+" "+q.Params.Args.Path+" "+string(q.Params.Args.Body))
		var v any
		switch {
		case q.Params.Name == "api_get" && q.Params.Args.Path == "/api/capture/interfaces":
			v = J{"ok": true, "data": J{"interfaces": []any{J{"name": "lo", "up": true}, J{"name": "eth0", "up": true}}, "gateway": []any{"eth1"}}}
		case q.Params.Name == "api_request" && q.Params.Args.Path == "/api/capture/job":
			v = J{"ok": true, "data": J{"id": "x", "running": true}}
		case q.Params.Name == "api_get" && strings.HasPrefix(q.Params.Args.Path, "/api/capture/job?id=netdir"):
			polls++
			if polls == 1 {
				v = J{"ok": true, "data": J{"done": false, "running": true}}
			} else {
				v = J{"ok": true, "data": J{"done": true, "kept": 5, "pcap": testPcap()}}
			}
		default:
			t.Errorf("unexpected call %v", seen[len(seen)-1])
		}
		j, _ := json.Marshal(v)
		_ = json.NewEncoder(w).Encode(J{"jsonrpc": "2.0", "id": q.ID, "result": J{"content": []any{J{"type": "text", "text": string(j)}}}})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	drv, err := Open(Device{Name: "d1", Platform: "dnsdir", Address: host, Port: pn, Insecure: true}, Credential{Name: "k", Token: "RWKEY"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := drv.(Capturer).Capture(context.Background(), CaptureReq{Filter: "udp and port 53", Seconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 5 || res.Interface != "eth1" || res.Protocols[0].Name != "DNS" {
		t.Errorf("%+v", res)
	}
	var start string
	for _, s := range seen {
		if strings.HasPrefix(s, "api_request POST /api/capture/job") {
			start = s
		}
	}
	if !strings.Contains(start, `"iface":"eth1"`) || !strings.Contains(start, `"filter":"udp and port 53"`) || !strings.Contains(start, `"seconds":1`) {
		t.Errorf("start call %q", start)
	}
	if polls != 2 {
		t.Errorf("polls %d", polls)
	}
	// a read-only key is refused by the director: the error says so
	d2, _ := Open(Device{Name: "d1", Platform: "dnsdir", Address: host, Port: pn, Insecure: true}, Credential{Name: "k", Token: "BAD"})
	if _, err := d2.(Capturer).Capture(context.Background(), CaptureReq{Interface: "eth0"}); err == nil {
		t.Error("a wrong key captured")
	}
}
