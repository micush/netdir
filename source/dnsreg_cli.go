package main

import (
	"fmt"
	"strconv"
	"strings"

	"netdir/internal/core"
)

// DNSRegState is the answer of dnsreg.status: the settings and what the last run did.
type DNSRegState struct {
	Config core.DNSRegConfig `json:"config"`
	Status core.DNSRegStatus `json:"status"`
}

// DNSRegState is the settings of this node and the state of its DNS registration.
func (m *Mgmt) DNSRegState() (DNSRegState, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return DNSRegState{}, err
	}
	st := DNSRegState{Status: core.DnsRegistrar.Status()}
	if dc.DNSReg != nil {
		st.Config = *dc.DNSReg
	}
	return st, nil
}

// DNSRegSet saves this node's DNS registration settings; the loop follows at once.
func (m *Mgmt) DNSRegSet(c core.DNSRegConfig, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	c.Key = strings.TrimSpace(c.Key)
	c.Domain, c.Server = strings.TrimSpace(c.Domain), strings.TrimSpace(c.Server)
	if err := c.Validate(); err != nil {
		return err
	}
	note := "dns registration: off"
	if c.Enabled {
		note = "dns registration: on"
	}
	if c.Empty() {
		dc.DNSReg = nil
	} else {
		dc.DNSReg = &c
	}
	return m.PutConfig(dc, actor, note)
}

// DNSRegRun registers (or removes) this node's records now and returns the state.
func (m *Mgmt) DNSRegRun(remove bool, actor string) (DNSRegState, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return DNSRegState{}, err
	}
	if remove {
		core.Infof("DNS registration: records removed by %s", actor)
	}
	st := core.DnsRegistrar.RunNow(dc, remove)
	out := DNSRegState{Status: st}
	if dc.DNSReg != nil {
		out.Config = *dc.DNSReg
	}
	return out, nil
}

// runDNSReg is the --dnsreg family:
//
//	--dnsreg                          show the settings and the last run
//	--dnsreg-enable | --dnsreg-disable   start / stop registering (settings kept; the records stay in DNS)
//	--dnsreg-key KEY                  TSIG key: a BIND key file, or name:base64secret[:algorithm]  ("-" = none)
//	--dnsreg-domain D | --dnsreg-server HOST[:PORT] | --dnsreg-interval S | --dnsreg-ttl S | --dnsreg-skip PATTERNS   ("-" = default / none)
//	--dnsreg-now                      register now and show what was done
//	--dnsreg-remove                   take this node's records out of DNS
func runDNSReg(sock string, f *cliFlags) {
	var st DNSRegState
	core.Decode(core.Op(sock, "dnsreg.status", nil), &st)
	c := st.Config
	changed := false
	str := func(v string, dst *string) {
		if v == "" {
			return
		}
		if v == "-" {
			v = ""
		}
		*dst, changed = v, true
	}
	num := func(name, v string, dst *int) {
		if v == "" {
			return
		}
		n := 0
		if v != "-" {
			var err error
			if n, err = strconv.Atoi(v); err != nil {
				core.Fatalf("--%s: %q is not a number", name, v)
			}
		}
		*dst, changed = n, true
	}
	str(*f.dnsKey, &c.Key)
	str(*f.dnsDomain, &c.Domain)
	str(*f.dnsServer, &c.Server)
	num("dnsreg-interval", *f.dnsInterval, &c.Interval)
	num("dnsreg-ttl", *f.dnsTTL, &c.TTL)
	if v := *f.dnsSkip; v != "" {
		c.Skip = nil
		if v != "-" {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					c.Skip = append(c.Skip, p)
				}
			}
		}
		changed = true
	}
	if *f.dnsOff && *f.dnsOn {
		core.Fatalf("--dnsreg-disable and --dnsreg-enable cannot be used together")
	}
	if *f.dnsOff && c.Enabled {
		c.Enabled, changed = false, true
	}
	if *f.dnsOn && !c.Enabled {
		c.Enabled, changed = true, true
	}
	if changed {
		st = DNSRegState{}
		core.Decode(core.Op(sock, "dnsreg.set", c), &st)
	}
	switch {
	case *f.dnsRemove, *f.dnsNow: // into a fresh value: decoding over the old one keeps the fields the new answer leaves out (an old error)
		cmd := "dnsreg.now"
		if *f.dnsRemove {
			cmd = "dnsreg.remove"
		}
		st = DNSRegState{}
		core.Decode(core.Op(sock, cmd, nil), &st)
	}
	printDNSReg(st, *f.dnsNow || *f.dnsRemove)
}

func printDNSReg(st DNSRegState, listed bool) {
	c, s := st.Config, st.Status
	if !s.Enabled {
		fmt.Println("DNS registration is off on this node.")
		if c.Empty() {
			fmt.Printf("  Set it up with: %s --dnsreg-key NAME:SECRET --dnsreg-enable\n", strings.TrimSuffix(core.LogFileName, ".log"))
		} else {
			fmt.Println("  The settings are kept; turn it on with --dnsreg-enable.")
		}
	} else {
		fmt.Printf("DNS registration is on: every %ds, TTL %ds, %s\n", int(c.Every().Seconds()), c.Ttl(), map[bool]string{true: "TSIG key set", false: "no TSIG key"}[strings.TrimSpace(c.Key) != ""])
	}
	if s.LastRun == "" {
		return
	}
	fmt.Printf("  Last %s %s: %s.%s via %s\n", s.Action, s.LastRun, s.Hostname, s.Domain, core.OrDefault(s.Server, "?"))
	fmt.Printf("  Right already %d, updated %d, removed %d, failed %d\n", s.Existing, s.Updated, s.Removed, s.Failed)
	if s.LastError != "" {
		fmt.Printf("  Last error: %s\n", s.LastError)
	}
	if s.NextRun != "" && s.Enabled {
		fmt.Printf("  Next check: %s\n", s.NextRun)
	}
	if listed || s.Failed > 0 {
		for _, r := range s.Records {
			if !listed && r.Result != "failed" {
				continue
			}
			line := fmt.Sprintf("    %-8s %-5s %-40s %s", r.Result, r.Type, r.Name, r.Value)
			if r.Error != "" {
				line += "  (" + r.Error + ")"
			}
			fmt.Println(line)
		}
	}
}
