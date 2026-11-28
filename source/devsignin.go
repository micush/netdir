package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"netdir/device"
	"netdir/internal/core"
	"netdir/internal/devices"
)

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
	id := core.RandHex(12)
	now := time.Now()
	devices.EntraFlows.Lock()
	for k, f := range devices.EntraFlows.M {
		if now.After(f.Expires) {
			delete(devices.EntraFlows.M, k)
		}
	}
	if len(devices.EntraFlows.M) >= 20 {
		devices.EntraFlows.Unlock()
		return nil, errors.New("too many sign-ins are open; wait a few minutes")
	}
	devices.EntraFlows.M[id] = &devices.EntraFlow{Dev: *dev, Cred: cred.Name, Code: code, Expires: now.Add(time.Duration(code.ExpiresIn) * time.Second), Next: now.Add(time.Duration(code.Interval) * time.Second)}
	devices.EntraFlows.Unlock()
	core.Warnf("devices: %q started a Microsoft sign-in for %s", actor, dev.Name)
	return map[string]any{"id": id, "device": dev.Name, "user_code": code.UserCode, "verification_uri": code.VerificationURI, "expires_in": code.ExpiresIn, "interval": code.Interval}, nil
}

func (m *Mgmt) deviceSigninPoll(raw json.RawMessage, actor string) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	devices.EntraFlows.Lock()
	f := devices.EntraFlows.M[a.ID]
	if f != nil && time.Now().After(f.Expires) {
		delete(devices.EntraFlows.M, a.ID)
		f = nil
	}
	if f == nil {
		devices.EntraFlows.Unlock()
		return nil, errors.New("the sign-in has expired or is unknown: start again")
	}
	if time.Now().Before(f.Next) { // Microsoft is not asked faster than it said
		devices.EntraFlows.Unlock()
		return map[string]any{"state": "pending"}, nil
	}
	f.Next = time.Now().Add(time.Duration(f.Code.Interval) * time.Second)
	devices.EntraFlows.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt, pending, err := device.EntraPollSignin(ctx, f.Dev, f.Code.DeviceCode)
	if err != nil {
		devices.EntraFlows.Lock()
		delete(devices.EntraFlows.M, a.ID)
		devices.EntraFlows.Unlock()
		return nil, err
	}
	if pending {
		return map[string]any{"state": "pending"}, nil
	}
	devices.EntraFlows.Lock()
	delete(devices.EntraFlows.M, a.ID)
	devices.EntraFlows.Unlock()
	if err := m.setEntraToken(f.Cred, "", rt, actor, "Entra sign-in for "+f.Dev.Name); err != nil {
		return nil, fmt.Errorf("signed in, but the login could not be saved: %w", err)
	}
	core.Warnf("devices: %q signed in to Microsoft for %s", actor, f.Dev.Name)
	return map[string]any{"state": "done", "device": f.Dev.Name}, nil
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

// entraRefreshed is device.EntraRefreshed: Microsoft replaced a refresh token.  The old one keeps working until it ages out, so it is
// saved at most once a day per login (every save is a version in History and goes to every node).
func (m *Mgmt) entraRefreshed(cred, old, rt string) {
	devices.EntraSaved.Lock()
	recent := time.Since(devices.EntraSaved.At[cred]) < 24*time.Hour
	devices.EntraSaved.Unlock()
	if recent {
		return
	}
	saved, err := m.putEntraToken(cred, old, rt, "netdir", "Entra sign-in renewed")
	if err != nil {
		core.Warnf("devices: could not save the renewed Microsoft sign-in of login %s: %v", cred, err)
		return
	}
	if saved {
		devices.EntraSaved.Lock()
		devices.EntraSaved.At[cred] = time.Now()
		devices.EntraSaved.Unlock()
	}
}
