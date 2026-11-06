package main

import (
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

	"netdir/device"
)

// onePcap is a .pcap with one UDP packet 10.1.1.1.4000 > 10.1.1.2.53.
func onePcap() []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[20:], 1)
	f := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	f[14] = 0x45
	f[23] = 17
	copy(f[26:], net.ParseIP("10.1.1.1").To4())
	copy(f[30:], net.ParseIP("10.1.1.2").To4())
	binary.BigEndian.PutUint16(f[34:], 4000)
	binary.BigEndian.PutUint16(f[36:], 53)
	r := make([]byte, 16)
	binary.LittleEndian.PutUint32(r[8:], uint32(len(f)))
	binary.LittleEndian.PutUint32(r[12:], uint32(len(f)))
	return append(append(b, r...), f...)
}

// captureEnv is mcpEnv with a stub BIG-IP whose shell (util/bash) runs a capture: tcpdump makes the file, base64 prints it, rm removes it.
func captureEnv(t *testing.T, acl ...string) (func(msg string, hdr ...string) (int, map[string]any), *sync.Map) {
	t.Helper()
	files := &sync.Map{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var q struct {
			Args string `json:"utilCmdArgs"`
		}
		_ = json.Unmarshal(b, &q)
		cmd := strings.TrimSuffix(strings.TrimPrefix(q.Args, `-c "`), `"`)
		f := strings.Fields(cmd)
		out := ""
		switch {
		case r.URL.Path != "/mgmt/tm/util/bash":
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		case strings.Contains(cmd, "tcpdump"):
			for i, w := range f {
				if w == "-w" {
					files.Store(f[i+1], onePcap())
				}
			}
		case strings.HasPrefix(cmd, "base64 -w0 "):
			v, _ := files.Load(f[2])
			out = base64.StdEncoding.EncodeToString(v.([]byte))
		case strings.HasPrefix(cmd, "rm -f "):
			files.Delete(f[2])
		default:
			t.Errorf("unexpected shell command %q", cmd)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"commandResult": out})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	e, post := mcpEnv(t, acl...)
	dc, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	dc.Settings.DeviceCredentials = []device.Credential{{Name: "lab", Username: "admin", Password: "sw-secret-pw"}}
	dc.Settings.Devices = []device.Device{{Name: "lb1", Platform: "bigip", Address: host, Port: p, Credential: "lab", Insecure: true},
		{Name: "sw1", Platform: "iosxe", Address: host, Port: p, Credential: "lab", Insecure: true}}
	if err := e.mg.PutConfig(dc, "test", "devices"); err != nil {
		t.Fatal(err)
	}
	return post, files
}

func TestMCPDeviceCapture(t *testing.T) {
	post, files := captureEnv(t, "127.0.0.1")
	_, m := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if strings.Contains(strings.Join(toolNames(t, m), ","), "device_capture") {
		t.Error("a read-only caller is offered device_capture")
	}
	_, m = post(mcpCall("device_capture", `{"target":"lb1"}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "read-only") {
		t.Errorf("ro call: %v %s", isErr, txt)
	}

	post, files = captureEnv(t, "127.0.0.1 rw")
	_, m = post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if !strings.Contains(strings.Join(toolNames(t, m), ","), "device_capture") {
		t.Fatal("device_capture is not offered to an rw caller")
	}
	_, m = post(mcpCall("device_capture", `{"target":"lb1","filter":"udp and port 53","seconds":2}`))
	txt, isErr := toolResult(t, m)
	if isErr || !strings.Contains(txt, `"packets": 1`) && !strings.Contains(txt, `"packets":1`) || !strings.Contains(txt, "UDP") || !strings.Contains(txt, "DNS") {
		t.Fatalf("capture: %v %s", isErr, txt)
	}
	n := 0
	files.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Errorf("%d capture files left on the device", n)
	}
	// a platform without capture says so, and a bad filter never reaches a device
	_, m = post(mcpCall("device_capture", `{"target":"sw1"}`))
	if txt, _ := toolResult(t, m); !strings.Contains(txt, "cannot capture") {
		t.Errorf("iosxe: %s", txt)
	}
	_, m = post(mcpCall("device_capture", `{"target":"lb1","filter":"port 53; reboot"}`))
	if txt, _ := toolResult(t, m); !strings.Contains(txt, "filter") {
		t.Errorf("bad filter: %s", txt)
	}
}
