package devices

import (
	"fmt"
	"sync"
	"time"

	"netdir/device"
	"netdir/internal/core"
)

// Browser sign-in for an Entra device (device/entra_signin.go has the protocol):
//
//	POST /api/devices/signin        {"device": "entra"}  ->  {"id", "user_code", "verification_uri", "expires_in", "interval"}
//	POST /api/devices/signin/poll   {"id": "..."}        ->  {"state": "pending"} or {"state": "done", "device": "entra"}
//	netdir --device-signin entra
//
// The person opens the link on any computer, enters the code and signs in; the poll that sees it done stores the refresh token in the
// device's login (the token "rt:..."), which is shared by the cluster like every login.  Signing in changes a login, so it needs the
// access a device change needs: a read-only session is refused by authed, and there is no MCP tool for it.  The device code itself
// never leaves the daemon.

type EntraFlow struct {
	Dev     device.Device    `json:"-"`
	Cred    string           `json:"-"`
	Code    device.EntraCode `json:"-"`
	Expires time.Time        `json:"-"`
	Next    time.Time        `json:"-"`
}

var EntraFlows = struct {
	sync.Mutex
	M map[string]*EntraFlow `json:"-"`
}{M: map[string]*EntraFlow{}}

var EntraSaved = struct {
	sync.Mutex
	At map[string]time.Time `json:"-"`
}{At: map[string]time.Time{}}

// ---- the CLI ----

func RunDeviceSignin(sock, name string) {
	var s struct {
		ID, Device      string
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	core.Decode(core.Op(sock, "device.signin_start", map[string]any{"device": name}), &s)
	fmt.Printf("Open %s on any computer and enter the code %s\nWaiting for the sign-in (up to %d minutes)…\n", s.VerificationURI, s.UserCode, (s.ExpiresIn+59)/60)
	deadline := time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(max(s.Interval, 1)) * time.Second)
		var p struct {
			State string `json:"state"`
		}
		core.Decode(core.Op(sock, "device.signin_poll", map[string]any{"id": s.ID}), &p)
		if p.State == "done" {
			fmt.Printf("Signed in. %s now asks Microsoft Entra as that account.\n", s.Device)
			return
		}
	}
	core.Fatalf("the code expired: run it again")
}
