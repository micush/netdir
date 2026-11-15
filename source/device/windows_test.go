package device

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const winAdaptersJSON = `[{"name":"Ethernet","desc":"Intel(R) I350","status":"Up","mac":"00-15-5D-01-02-03","speed":1000000000,"mtu":1500,"full":true,"media":"802.3","ips":"192.0.2.20/24","rxb":1000,"rxu":10,"rxm":2,"rxd":1,"rxe":3,"txb":2000,"txu":20,"txd":0,"txe":0},
{"name":"Ethernet 2","desc":"Intel(R) I350 #2","status":"Disabled","mac":"00-15-5D-01-02-04","speed":0,"mtu":1500,"full":null,"media":"802.3","ips":[],"rxb":0,"rxu":0,"rxm":0,"rxd":0,"rxe":0,"txb":0,"txu":0,"txd":0,"txe":0}]`

type fakeWin struct {
	disabled map[string]bool
	scripts  []string
	fail     string
}

func (f *fakeWin) exec(_ context.Context, t linuxTarget, script string, _ bool) (string, string, error) {
	if !t.Win {
		return "", "", errors.New("not a windows target")
	}
	f.scripts = append(f.scripts, script)
	if f.fail != "" && strings.Contains(script, f.fail) {
		return "partial\n", "The term 'badcmd' is not recognized\n", errors.New("exit status 1")
	}
	switch {
	case strings.Contains(script, "Get-NetAdapterStatistics"):
		js := winAdaptersJSON
		for n, d := range f.disabled {
			st := map[bool]string{true: "Disabled", false: "Up"}[d]
			js = regexp.MustCompile(`("name":"`+regexp.QuoteMeta(n)+`","desc":"[^"]*","status":)"[A-Za-z]+"`).ReplaceAllString(js, `$1"`+st+`"`)
		}
		return "\ufeff" + js, "", nil
	case strings.Contains(script, "Win32_BIOS"):
		return `{"host":"WIN1","dns":"win1","domain":"corp.example.com","os":"Microsoft Windows Server 2022 Standard","version":"10.0.20348","build":"20348","up":7200,"model":"Virtual Machine","vendor":"Microsoft Corporation","serial":"1234-5678"}`, "", nil
	case strings.Contains(script, "Get-NetRoute"):
		return `[{"dst":"0.0.0.0/0","gw":"192.0.2.1","dev":"Ethernet","metric":25,"proto":"NetMgmt"},{"dst":"192.0.2.0/24","gw":"0.0.0.0","dev":"Ethernet","metric":281,"proto":"Local"}]`, "", nil
	case strings.Contains(script, "Win32_Processor | Measure-Object"):
		return `{"cpu":12.5,"memtotal":8000,"memfree":6000,"swaptotal":0,"swapfree":0,"disks":{"name":"C:","size":1000,"free":250}}`, "", nil
	case strings.Contains(script, "Disable-NetAdapter") || strings.Contains(script, "Enable-NetAdapter"):
		for _, ln := range strings.Split(script, "\n") {
			if m := regexp.MustCompile(`^(Disable|Enable)-NetAdapter -Name '([^']+)' -Confirm:\$false$`).FindStringSubmatch(ln); m != nil {
				f.disabled[m[2]] = m[1] == "Disable"
			}
		}
		return "", "", nil
	case strings.Contains(script, "Get-NetIPAddress | Sort-Object"):
		return "InterfaceAlias IPAddress\nEthernet 192.0.2.20\n", "", nil
	}
	return "", "", nil
}

func useFakeWin(t *testing.T) (*fakeWin, *windows) {
	t.Helper()
	f := &fakeWin{disabled: map[string]bool{"Ethernet 2": true, "Ethernet": false}}
	old := linuxExec
	linuxExec = f.exec
	t.Cleanup(func() { linuxExec = old })
	d, err := newWindows(Device{Name: "win1", Platform: "windows", Address: "192.0.2.20"}, Credential{Username: `CORP\admin`, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	return f, d.(*windows)
}

func TestWindowsReads(t *testing.T) {
	_, w := useFakeWin(t)
	ctx := context.Background()
	f, err := w.Facts(ctx)
	if err != nil || f.Hostname != "win1.corp.example.com" || f.UptimeS != 7200 || !strings.Contains(f.OSVersion, "Server 2022") || f.Serial != "1234-5678" || !strings.Contains(f.Model, "Virtual Machine") {
		t.Fatalf("facts %+v %v", f, err)
	}
	ifs, err := w.Interfaces(ctx)
	if err != nil || len(ifs) != 2 {
		t.Fatalf("interfaces %+v %v", ifs, err)
	}
	if e := ifs[0]; e.Name != "Ethernet" || !*e.AdminUp || !*e.OperUp || e.SpeedMbps != 1000 || e.MAC != "00:15:5d:01:02:03" || len(e.Addresses) != 1 || e.Addresses[0] != "192.0.2.20/24" {
		t.Errorf("eth %+v", e)
	}
	if e := ifs[1]; *e.AdminUp || *e.OperUp || len(e.Addresses) != 0 {
		t.Errorf("eth2 %+v", e)
	}
	ps, err := w.Ports(ctx)
	if err != nil || ps[0].Counters.InOctets != 1000 || ps[0].Counters.InErrors != 3 || ps[0].Duplex != "full" || ps[1].Duplex != "" {
		t.Fatalf("ports %+v %v", ps, err)
	}
	rs, err := w.Routes(ctx)
	if err != nil || len(rs) != 2 || rs[0].NextHop != "192.0.2.1" || rs[1].NextHop != "" {
		t.Fatalf("routes %+v %v", rs, err)
	}
	r, err := w.Resources(ctx)
	if err != nil || r.CPU.Now != 12.5 || r.Memory[0].UsedPercent != 25 || len(r.Storage) != 1 || r.Storage[0].UsedPercent != 75 {
		t.Fatalf("resources %+v %v", r, err)
	}
	if _, err := w.Neighbors(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("neighbors %v", err)
	}
}

func TestWindowsShow(t *testing.T) {
	_, w := useFakeWin(t)
	ctx := context.Background()
	out, err := w.Show(ctx, "show ip | include 192")
	if err != nil || strings.TrimSpace(out) != "Ethernet 192.0.2.20" {
		t.Fatalf("%q %v", out, err)
	}
	for _, bad := range []string{"Get-Process", "show", "show service x'; Remove-Item", "show log Foo", "show nothing", "show ip > c:\\x"} {
		if _, err := w.Show(ctx, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	s, err := winShow(strings.Fields("show service Windows Update"))
	if err != nil || !strings.Contains(s, "'Windows Update'") {
		t.Errorf("%q %v", s, err)
	}
	if s, _ := winShow(strings.Fields("show eventlog 99999")); !strings.Contains(s, "-MaxEvents 300") {
		t.Errorf("not capped: %s", s)
	}
}

func TestWindowsTypedChange(t *testing.T) {
	f, w := useFakeWin(t)
	ctx := context.Background()
	ports, err := ParsePorts("ethernet2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Change(ctx, Change{Action: ActNoShutdown, Ports: ports}, false); err != nil || f.disabled["Ethernet 2"] {
		t.Fatalf("no shutdown: %v %v", err, f.disabled)
	}
	last := f.scripts[len(f.scripts)-2] // the change; the last script is the read-back
	if !strings.Contains(last, "Enable-NetAdapter -Name 'Ethernet 2' -Confirm:$false") {
		t.Errorf("script %q", last)
	}
	if _, err := w.Change(ctx, Change{Action: ActDescription, Ports: []string{"Ethernet"}, Value: "x"}, false); err == nil {
		t.Error("description accepted")
	}
	if _, err := w.Change(ctx, Change{Action: ActClearCounters, Ports: []string{AllPorts}}, false); err == nil {
		t.Error("clear counters accepted")
	}
	n := len(f.scripts)
	if _, err := w.Change(ctx, Change{Action: ActShutdown, Ports: []string{"Ethernet 9"}}, false); err == nil {
		t.Errorf("unknown adapter accepted")
	}
	for _, sc := range f.scripts[n:] {
		if strings.Contains(sc, "Disable-NetAdapter") {
			t.Errorf("something was sent for an adapter the host lacks: %s", sc)
		}
	}
	// Ethernet holds the address the gateway uses: refused while the lists are on
	if _, err := w.Change(ctx, Change{Action: ActShutdown, Ports: []string{"Ethernet"}}, false); err == nil || f.disabled["Ethernet"] {
		t.Errorf("management adapter shut: %v", err)
	}
	if got, err := ParsePorts("Ethernet wi-fi"); err != nil || len(got) != 2 {
		t.Errorf("%v %v", got, err)
	}
}

func TestWindowsRawChange(t *testing.T) {
	f, w := useFakeWin(t)
	ctx := context.Background()
	res, err := w.RawChange(ctx, Raw{Lines: []string{"Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 192.0.2.53"}}, true)
	if err != nil || !res.DryRun || res.Applied || len(f.scripts) != 0 {
		t.Fatalf("dry %+v %v", res, err)
	}
	res, err = w.RawChange(ctx, Raw{Lines: []string{"New-Item -ItemType Directory C:\\x", "Get-Date"}}, false)
	if err != nil || !res.Applied || !strings.HasPrefix(f.scripts[0], "$ErrorActionPreference='Stop'\n") {
		t.Fatalf("run %+v %v %v", res, err, f.scripts)
	}
	f.fail = "badcmd"
	if res, err := w.RawChange(ctx, Raw{Lines: []string{"badcmd"}}, false); err == nil || res.Applied || !strings.Contains(err.Error(), "not undone") || !strings.Contains(res.Answer, "partial") {
		t.Errorf("failure %+v %v", res, err)
	}
	if _, err := w.RawChange(ctx, Raw{Lines: []string{"Restart-Computer -Force"}}, false); err == nil {
		t.Error("restart sent with the lists on")
	}
	if _, err := w.RawChange(ctx, Raw{Path: "/x"}, false); err == nil {
		t.Error("a path was accepted")
	}
	SetGuards(false)
	defer SetGuards(true)
	f.fail = ""
	if res, err := w.RawChange(ctx, Raw{Lines: []string{"New-LocalUser bob"}}, false); err != nil || !res.Applied {
		t.Errorf("with the lists off: %+v %v", res, err)
	}
}

func TestWinInvocation(t *testing.T) {
	script := "Get-Date\n'it''s'\n"
	remote, stdin := winInvocation(script)
	if !strings.HasPrefix(remote, "powershell -NoProfile -NonInteractive") || !strings.HasSuffix(remote, "-Command -") || strings.Contains(remote, "Get-Date") {
		t.Errorf("remote %q", remote)
	}
	m := regexp.MustCompile(`FromBase64String\('([A-Za-z0-9+/=]+)'\)`).FindStringSubmatch(stdin)
	if m == nil || strings.Count(stdin, "\n") != 1 || !strings.HasSuffix(stdin, "\n") {
		t.Fatalf("stdin %q", stdin)
	}
	if b, _ := base64.StdEncoding.DecodeString(m[1]); string(b) != script {
		t.Errorf("decoded %q", b)
	}
}

func TestNewWindowsChecks(t *testing.T) {
	ok := Credential{Username: "admin", Password: "x"}
	for _, d := range []Device{{Address: "-oX"}, {Address: ""}, {Address: "a b"}} {
		if _, err := newWindows(d, ok); err == nil {
			t.Errorf("address %q accepted", d.Address)
		}
	}
	for _, u := range []string{"", "-oX", "a b", "a;b", "a'b"} {
		if _, err := newWindows(Device{Address: "h"}, Credential{Username: u}); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	for _, u := range []string{`CORP\admin`, "admin@corp.example.com", "Administrator"} {
		if _, err := newWindows(Device{Address: "h"}, Credential{Username: u}); err != nil {
			t.Errorf("user %q: %v", u, err)
		}
	}
}

// the stand-in ssh: the script travels on standard input, not in the arguments, and the password is not in either.
func TestSSHExecWindows(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "rec")
	fake := filepath.Join(dir, "ssh")
	os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+rec+".args\ncat > "+rec+".stdin\necho out\n"), 0o755)
	t.Setenv("NETDIR_SSH", fake)
	t.Setenv("NETDIR_SSH_KNOWN_HOSTS", filepath.Join(dir, "kh"))
	so, _, err := sshExec(context.Background(), linuxTarget{Host: "w1", Port: 22, User: `CORP\admin`, Pass: "s3cret", Win: true, Sudo: true}, "Get-Date", true)
	if err != nil || so != "out\n" {
		t.Fatalf("%q %v", so, err)
	}
	args, _ := os.ReadFile(rec + ".args")
	in, _ := os.ReadFile(rec + ".stdin")
	if !strings.Contains(string(args), "powershell -NoProfile") || strings.Contains(string(args), "s3cret") || strings.Contains(string(in), "s3cret") || !strings.Contains(string(in), "FromBase64String") || !strings.Contains(string(args), `CORP\admin`) {
		t.Errorf("args:\n%s\nstdin:\n%s", args, in)
	}
}

var (
	_ Changer    = (*windows)(nil)
	_ Porter     = (*windows)(nil)
	_ Router     = (*windows)(nil)
	_ Resourcer  = (*windows)(nil)
	_ RawChanger = (*windows)(nil)
)
