package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"netdir/internal/cluster"
	"netdir/internal/core"
)

// ── a real capture (needs the socket; skipped where the sandbox does not allow it) ──

func canCapture(t *testing.T) {
	t.Helper()
	cs := &core.CaptureState{}
	if err := cs.StartOn("lo", ""); err != nil {
		t.Skipf("no raw sockets here: %v", err)
	}
	cs.Stop()
}

func sendUDP(t *testing.T, port int, n int) {
	t.Helper()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", core.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < n; i++ {
		c.Write([]byte("netdir capture test"))
		time.Sleep(5 * time.Millisecond)
	}
}

// ── the web side ─────────────────────────────────────────────────────────────

func TestCaptureHTTP(t *testing.T) {
	canCapture(t)
	e := newWebEnv(t)
	e.login("alice", "pw")
	r := e.do("GET", "/api/capture/interfaces", nil, withAuth(e, false))
	var ifs struct {
		Data CaptureInterfaces `json:"data"`
	}
	json.Unmarshal(r.raw, &ifs)
	if r.code != 200 || len(ifs.Data.Interfaces) == 0 {
		t.Fatalf("interfaces: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/capture/start", map[string]string{"iface": "lo", "filter": "port nine"}, withAuth(e, true)); r.code != http.StatusUnprocessableEntity || !strings.Contains(string(r.raw), "filter") {
		t.Fatalf("a bad filter: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/capture/start", map[string]string{"iface": "lo", "filter": "udp"}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("start: %d %s", r.code, r.raw)
	}
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer l.Close()
	sendUDP(t, l.LocalAddr().(*net.UDPAddr).Port, 3)
	time.Sleep(300 * time.Millisecond)
	r = e.do("GET", "/api/capture/packets?since=0", nil, withAuth(e, false))
	var pk struct {
		Data core.CapStatus `json:"data"`
	}
	json.Unmarshal(r.raw, &pk)
	if !pk.Data.Running || pk.Data.Iface != "lo" || len(pk.Data.Packets) < 3 {
		t.Fatalf("packets: %s", r.raw)
	}
	r = e.do("GET", "/api/capture/download", nil, withAuth(e, false))
	if r.code != 200 || r.hdr.Get("Content-Type") != "application/gzip" || !strings.HasSuffix(r.hdr.Get("Content-Disposition"), `.tgz"`) {
		t.Fatalf("download: %d %v", r.code, r.hdr)
	}
	zr, err := gzip.NewReader(bytes.NewReader(r.raw))
	if err != nil {
		t.Fatalf("not a gzip: %v", err)
	}
	tr := tar.NewReader(zr)
	hd, err := tr.Next()
	if err != nil || !strings.HasSuffix(hd.Name, ".pcap") {
		t.Fatalf("the archive's first file: %v %+v", err, hd)
	}
	pcapBytes, _ := io.ReadAll(tr)
	if _, p, err := core.ReadPcap(pcapBytes); err != nil || len(p) < 3 {
		t.Fatalf("the pcap: %v %d", err, len(p))
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("the archive holds more than the one .pcap: %v", err)
	}
	if r := e.do("GET", "/api/capture/pcap", nil, withAuth(e, false)); r.code == 200 {
		t.Fatalf("the old .pcap download still answers")
	}
	if r := e.do("POST", "/api/capture/clear", map[string]string{}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("clear: %d", r.code)
	}
	json.Unmarshal(e.do("GET", "/api/capture/packets?since=0", nil, withAuth(e, false)).raw, &pk)
	if len(pk.Data.Packets) != 0 {
		t.Fatalf("not cleared: %d", len(pk.Data.Packets))
	}
	e.do("POST", "/api/capture/stop", map[string]string{}, withAuth(e, true))
	json.Unmarshal(e.do("GET", "/api/capture/packets?since=0", nil, withAuth(e, false)).raw, &pk)
	if pk.Data.Running {
		t.Fatal("still running after stop")
	}
	// not logged in
	if r := e.do("GET", "/api/capture/interfaces", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", r.code)
	}
	// a timed capture is started and then asked for; its time is bounded
	if r := e.do("POST", "/api/capture/job", map[string]any{"id": "t0", "iface": "lo", "seconds": 61}, withAuth(e, true)); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("61 s: %d", r.code)
	}
	if r := e.do("POST", "/api/capture/job", map[string]any{"id": "t1", "iface": "lo", "filter": "udp", "seconds": 1}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("job start: %d %s", r.code, r.raw)
	}
	var st struct {
		Data CaptureRunStatus `json:"data"`
	}
	for i := 0; i < 40; i++ {
		time.Sleep(100 * time.Millisecond)
		json.Unmarshal(e.do("GET", "/api/capture/job?id=t1", nil, withAuth(e, false)).raw, &st)
		if st.Data.Done {
			break
		}
	}
	if !st.Data.Done || st.Data.Error != "" || len(st.Data.Pcap) < 24 || st.Data.Iface != "lo" {
		t.Fatalf("job: %+v", st.Data)
	}
	if r := e.do("GET", "/api/capture/job?id=nope", nil, withAuth(e, false)); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown job: %d", r.code)
	}
}

// ── every node ───────────────────────────────────────────────────────────────

func tgzFiles(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		d, _ := io.ReadAll(tr)
		out[h.Name] = d
	}
	return out
}

func waitJob(t *testing.T, m *Mgmt) *CaptureJob {
	t.Helper()
	for i := 0; i < 200; i++ {
		if j := m.CaptureClusterStatus(); j != nil && j.Done {
			return j
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the cluster capture never finished")
	return nil
}

func TestClusterCaptureBundlesEveryNode(t *testing.T) {
	canCapture(t)
	a, b := twoNodeCluster(t)
	withWeb(t, a)
	withWeb(t, b)
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer l.Close()
	port := l.LocalAddr().(*net.UDPAddr).Port
	if _, err := a.mg.CaptureClusterStart("lo", "udp and dst port "+core.Itoa(port), 2, 0, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.mg.CaptureClusterStart("lo", "", 2, 0, "tester"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("a second job at once: %v", err)
	}
	time.Sleep(600 * time.Millisecond)
	sendUDP(t, port, 3)
	j := waitJob(t, a.mg)
	if !j.Ready || len(j.Nodes) != 2 {
		t.Fatalf("job: %+v", j)
	}
	selves := 0
	for _, n := range j.Nodes {
		if n.Status != "done" || n.Kept != 3 {
			t.Errorf("node %+v", n)
		}
		if n.Self {
			selves++
		}
	}
	if selves != 1 || !j.Nodes[0].Self {
		t.Errorf("this node is marked %d times, first %v", selves, j.Nodes[0].Self)
	}
	tgz, err := a.mg.CaptureClusterBundle()
	if err != nil {
		t.Fatal(err)
	}
	files := tgzFiles(t, tgz)
	pcaps := 0
	for name, d := range files {
		if strings.HasSuffix(name, ".pcap") {
			pcaps++
			if _, p, err := core.ReadPcap(d); err != nil || len(p) != 3 {
				t.Errorf("%s: %v %d", name, err, len(p))
			}
		}
	}
	if pcaps != 2 || len(files["summary.txt"]) == 0 || files["errors.txt"] != nil {
		t.Fatalf("bundle: %v", keys(files))
	}

	// a node that cannot be asked is named in errors.txt and the others still make the bundle
	b.mg.webH = nil
	if _, err := a.mg.CaptureClusterStart("lo", "", 1, 0, "tester"); err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, a.mg)
	bad := 0
	for _, n := range j.Nodes {
		if n.Status == "error" && n.Error != "" {
			bad++
		}
	}
	files = tgzFiles(t, mustBundle(t, a.mg))
	if bad != 1 || !j.Ready || files["errors.txt"] == nil {
		t.Fatalf("one node down: bad %d ready %v files %v", bad, j.Ready, keys(files))
	}
	// an interface the nodes do not have: every node says so, and there is nothing to download
	if _, err := a.mg.CaptureClusterStart("nonesuch0", "", 1, 0, "tester"); err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, a.mg)
	if j.Ready || j.Error == "" {
		t.Fatalf("a missing interface: %+v", j)
	}
	if _, err := a.mg.CaptureClusterBundle(); err == nil {
		t.Error("a bundle of nothing")
	}
}

func TestClusterCaptureRefusals(t *testing.T) {
	e := newWebEnv(t)
	for _, c := range []struct {
		iface, filter string
		secs          int
		want          string
	}{{"lo", "", 0, "1 to 60"}, {"lo", "", 61, "1 to 60"}, {"", "", 5, "interface"}, {"lo", "port x", 5, "filter"}} {
		if _, err := e.mg.CaptureClusterStart(c.iface, c.filter, c.secs, 0, "t"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func keys(m map[string][]byte) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

func mustBundle(t *testing.T, m *Mgmt) []byte {
	t.Helper()
	b, err := m.CaptureClusterBundle()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ── timed captures started on a node and asked for ───────────────────────────

func TestCaptureJobIsIdempotentAndBounded(t *testing.T) {
	canCapture(t)
	e := newWebEnv(t)
	a, err := e.mg.CaptureJobStart("same", "lo", "udp", 1, "t")
	if err != nil || !a.Running {
		t.Fatalf("start: %v %+v", err, a)
	}
	if _, err := e.mg.CaptureJobStart("same", "lo", "udp", 1, "t"); err != nil {
		t.Fatalf("the same id again: %v", err)
	}
	e.mg.capruns.mu.Lock()
	n := len(e.mg.capruns.m)
	e.mg.capruns.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d captures for one id (a request sent twice must not start two)", n)
	}
	for _, bad := range []string{"", strings.Repeat("x", 41), "a b", "a/b", "a?b"} {
		if _, err := e.mg.CaptureJobStart(bad, "lo", "", 1, "t"); err == nil {
			t.Errorf("id %q accepted", bad)
		}
	}
	if _, err := e.mg.CaptureJobStart("x2", "nope0", "", 1, "t"); err == nil || !strings.Contains(err.Error(), "no interface") {
		t.Errorf("a missing interface must be refused when the capture starts: %v", err)
	}
	for i := 0; i < capRunsKept; i++ {
		e.mg.CaptureJobStart("fill"+core.Itoa(i), "lo", "", 1, "t")
	}
	if _, err := e.mg.CaptureJobStart("one-too-many", "lo", "", 1, "t"); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("no limit on held captures: %v", err)
	}
	time.Sleep(1300 * time.Millisecond)
	st, err := e.mg.CaptureJobGet("same")
	if err != nil || !st.Done || len(st.Pcap) < 24 {
		t.Fatalf("get: %v %+v", err, st)
	}
	if _, err := e.mg.CaptureJobGet("never"); err == nil {
		t.Error("an unknown capture was found")
	}
}

// A capture longer than the few seconds the peer channel gives one address must work, and start once on each node: the
// first version of the cluster capture asked each node to hold one request open for the whole time, so every address
// "timed out" and the request was sent again to the next one.
func TestClusterCaptureOutlastsTheFailoverTimeout(t *testing.T) {
	canCapture(t)
	a, b := twoNodeCluster(t)
	withWeb(t, a)
	withWeb(t, b)
	peer := a.mg.cl.Node.Snapshot().Peers[0]
	if n := len(a.mg.cl.AddrsFor(peer)); n < 2 {
		t.Skipf("the peer has one address (%d): nothing to fail over to", n)
	}
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer l.Close()
	port := l.LocalAddr().(*net.UDPAddr).Port
	if _, err := a.mg.CaptureClusterStart("lo", "udp and dst port "+core.Itoa(port), 8, 0, "tester"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	sendUDP(t, port, 3)
	j := waitJob(t, a.mg)
	if !j.Ready {
		t.Fatalf("job: %+v", j)
	}
	for _, n := range j.Nodes {
		if n.Status != "done" || n.Kept != 3 {
			t.Errorf("node %+v", n)
		}
	}
	for name, mg := range map[string]*Mgmt{"a": a.mg, "b": b.mg} {
		mg.capruns.mu.Lock()
		n := len(mg.capruns.m)
		mg.capruns.mu.Unlock()
		if n != 1 {
			t.Errorf("node %s ran %d captures for one job", name, n)
		}
	}
}

// What the cluster reads from the configuration: the VIPs and the anycast addresses, in any spelling.
func TestSharedAddrsComeFromTheGateways(t *testing.T) {
	e := newWebEnv(t)
	dc, _, _ := e.mg.LiveConfig()
	g := core.DefaultGroup()
	g.GroupID, g.VIP4, g.VIP6, g.ExtraVIPs = 1, "10.20.0.205/28", "2620:ad:8081:c0cf:10:129:0:205/64", []string{"192.168.168.168", "fd00::123/128"}
	dc.Groups = []core.GroupConfig{g}
	if err := e.mg.PutConfig(dc, "t", ""); err != nil {
		t.Skipf("cannot set the test config: %v", err)
	}
	c := &cluster.Cluster{Mg: e.mg}
	sh := c.SharedAddrs()
	for _, want := range []string{"10.20.0.205", "2620:ad:8081:c0cf:10:129:0:205", "192.168.168.168", "fd00::123"} {
		if !sh[want] {
			t.Errorf("%s is not among the shared addresses %v", want, sh)
		}
	}
}

func TestGatewayCaptureFilter(t *testing.T) {
	gc := &core.GroupConfig{VIP4: "192.0.2.10/24", VIP6: "2001:db8::10/64", MoreVIP4: []string{"192.0.2.11", "192.0.2.10"}, ExtraVIPs: []string{"198.51.100.123/32"}}
	got := gatewayCapHosts(gc)
	if got != "host 192.0.2.10 or host 2001:db8::10 or host 192.0.2.11 or host 198.51.100.123" {
		t.Fatalf("%q", got)
	}
	for _, f := range []string{got, "(" + got + ") and (udp and port 123)"} {
		if _, err := core.CompileCapFilter(f); err != nil {
			t.Fatalf("%q: %v", f, err)
		}
	}
	if gatewayCapHosts(&core.GroupConfig{}) != "" {
		t.Fatal("no address, no filter")
	}
}

// A gateway's capture runs on its interface, keeps only its addresses, and refuses a gateway that does not exist.
func TestClusterCaptureOfAGateway(t *testing.T) {
	e := newWebEnv(t)
	dc := core.NewDaemonConfig()
	dc.Cluster.Enabled = false
	g := core.DefaultGroup()
	g.GroupID, g.Interface, g.VIP4, g.VIP6 = 7, "lo", "127.0.0.77/8", ""
	dc.Groups = []core.GroupConfig{g}
	b, _ := json.MarshalIndent(dc, "", "  ")
	if err := os.WriteFile(e.conf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadConfig(e.conf); err != nil {
		t.Fatal(err)
	}
	job, err := e.mg.CaptureClusterStart("", "udp", 1, 7, "t")
	if err != nil {
		t.Fatal(err)
	}
	if job.Iface != "lo" || job.Gateway != 7 || job.Filter != "(host 127.0.0.77) and (udp)" {
		t.Fatalf("%+v", job)
	}
	for i := 0; i < 100; i++ { // let it finish
		if st := e.mg.CaptureClusterStatus(); st != nil && st.Done {
			if st.Gateway != 7 {
				t.Fatalf("the status must say which gateway: %+v", st)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := e.mg.CaptureClusterStart("", "", 1, 999, "t"); err == nil {
		t.Fatal("a gateway that does not exist was accepted")
	}
	// a capture of the gateway keeps the filter within its limit
	if _, err := e.mg.CaptureClusterStart("", "udp"+strings.Repeat(" ", core.CapFilterMax-3), 1, 7, "t"); err == nil {
		t.Fatal("a filter pushed over the limit by the gateway's addresses was accepted")
	}
}
