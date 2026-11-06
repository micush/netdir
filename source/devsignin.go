package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"netdir/device"
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

type entraFlow struct {
	dev     device.Device
	cred    string
	code    device.EntraCode
	expires time.Time
	next    time.Time
}

var entraFlows = struct {
	sync.Mutex
	m map[string]*entraFlow
}{m: map[string]*entraFlow{}}

func (m *Mgmt) deviceSigninStart(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		Device string `json:"device"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	var dev *device.Device
	for i := range dc.Settings.Devices {
		if dc.Settings.Devices[i].Name == a.Device {
			dev = &dc.Settings.Devices[i]
		}
	}
	if dev == nil {
		return nil, fmt.Errorf("device %q: not in the inventory", a.Device)
	}
	if dev.Platform != "entra" {
		return nil, fmt.Errorf("device %s: only an Entra device is signed in with a browser", dev.Name)
	}
	var cred *device.Credential
	for i := range dc.Settings.DeviceCredentials {
		if dc.Settings.DeviceCredentials[i].Name == dev.Credential {
			cred = &dc.Settings.DeviceCredentials[i]
		}
	}
	if cred == nil {
		return nil, fmt.Errorf("device %s: its login %q does not exist", dev.Name, dev.Credential)
	}
	if !strings.HasPrefix(cred.Token, "rt:") {
		return nil, fmt.Errorf("device %s: its login %q holds an application secret, not a browser sign-in; give the device a new login with nothing filled in", dev.Name, cred.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code, err := device.EntraStartSignin(ctx, *dev)
	if err != nil {
		return nil, err
	}
	id := randHex(12)
	now := time.Now()
	entraFlows.Lock()
	for k, f := range entraFlows.m {
		if now.After(f.expires) {
			delete(entraFlows.m, k)
		}
	}
	if len(entraFlows.m) >= 20 {
		entraFlows.Unlock()
		return nil, errors.New("too many sign-ins are open; wait a few minutes")
	}
	entraFlows.m[id] = &entraFlow{dev: *dev, cred: cred.Name, code: code, expires: now.Add(time.Duration(code.ExpiresIn) * time.Second), next: now.Add(time.Duration(code.Interval) * time.Second)}
	entraFlows.Unlock()
	warnf("devices: %q started a Microsoft sign-in for %s", actor, dev.Name)
	return map[string]any{"id": id, "device": dev.Name, "user_code": code.UserCode, "verification_uri": code.VerificationURI, "expires_in": code.ExpiresIn, "interval": code.Interval}, nil
}

func (m *Mgmt) deviceSigninPoll(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	entraFlows.Lock()
	f := entraFlows.m[a.ID]
	if f != nil && time.Now().After(f.expires) {
		delete(entraFlows.m, a.ID)
		f = nil
	}
	if f == nil {
		entraFlows.Unlock()
		return nil, errors.New("the sign-in has expired or is unknown: start again")
	}
	if time.Now().Before(f.next) { // Microsoft is not asked faster than it said
		entraFlows.Unlock()
		return map[string]any{"state": "pending"}, nil
	}
	f.next = time.Now().Add(time.Duration(f.code.Interval) * time.Second)
	entraFlows.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt, pending, err := device.EntraPollSignin(ctx, f.dev, f.code.DeviceCode)
	if err != nil {
		entraFlows.Lock()
		delete(entraFlows.m, a.ID)
		entraFlows.Unlock()
		return nil, err
	}
	if pending {
		return map[string]any{"state": "pending"}, nil
	}
	entraFlows.Lock()
	delete(entraFlows.m, a.ID)
	entraFlows.Unlock()
	if err := m.setEntraToken(f.cred, "", rt, actor, "Entra sign-in for "+f.dev.Name); err != nil {
		return nil, fmt.Errorf("signed in, but the login could not be saved: %w", err)
	}
	warnf("devices: %q signed in to Microsoft for %s", actor, f.dev.Name)
	return map[string]any{"state": "done", "device": f.dev.Name}, nil
}

// setEntraToken stores a refresh token in a login.  With old set, it does so only while the login still holds that token (a newer
// sign-in is not overwritten by a renewal).
func (m *Mgmt) setEntraToken(cred, old, rt, actor, note string) error {
	_, err := m.putEntraToken(cred, old, rt, actor, note)
	return err
}

func (m *Mgmt) putEntraToken(cred, old, rt, actor, note string) (bool, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return false, err
	}
	for i := range dc.Settings.DeviceCredentials {
		c := &dc.Settings.DeviceCredentials[i]
		if c.Name != cred {
			continue
		}
		if old != "" && c.Token != device.EntraStoredToken(old) {
			return false, nil
		}
		c.Username, c.Password, c.Token = "", "", device.EntraStoredToken(rt)
		return true, m.PutConfig(dc, actor, note)
	}
	return false, fmt.Errorf("login %q does not exist", cred)
}

var entraSaved = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// entraRefreshed is device.EntraRefreshed: Microsoft replaced a refresh token.  The old one keeps working until it ages out, so it is
// saved at most once a day per login (every save is a version in History and goes to every node).
func (m *Mgmt) entraRefreshed(cred, old, rt string) {
	entraSaved.Lock()
	recent := time.Since(entraSaved.at[cred]) < 24*time.Hour
	entraSaved.Unlock()
	if recent {
		return
	}
	saved, err := m.putEntraToken(cred, old, rt, "netdir", "Entra sign-in renewed")
	if err != nil {
		warnf("devices: could not save the renewed Microsoft sign-in of login %s: %v", cred, err)
		return
	}
	if saved {
		entraSaved.Lock()
		entraSaved.at[cred] = time.Now()
		entraSaved.Unlock()
	}
}

// ---- the CLI ----

func runDeviceSignin(sock, name string) {
	var s struct {
		ID, Device      string
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	decode(op(sock, "device.signin_start", map[string]any{"device": name}), &s)
	fmt.Printf("Open %s on any computer and enter the code %s\nWaiting for the sign-in (up to %d minutes)…\n", s.VerificationURI, s.UserCode, (s.ExpiresIn+59)/60)
	deadline := time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(max(s.Interval, 1)) * time.Second)
		var p struct {
			State string `json:"state"`
		}
		decode(op(sock, "device.signin_poll", map[string]any{"id": s.ID}), &p)
		if p.State == "done" {
			fmt.Printf("Signed in. %s now asks Microsoft Entra as that account.\n", s.Device)
			return
		}
	}
	fatalf("the code expired: run it again")
}
