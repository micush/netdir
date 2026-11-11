package device

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// tools is not a device on the network: it is the network tools (ping, mtr, nmap, dig, curl, whois) of the netdir node a gateway runs
// on.  Adding this device to a gateway turns the tools on for that gateway: the assistant's net_* tools run from the node that serves
// it (mcpnettools.go).  It needs no address and no login.  Facts say which of the programs the node has.
type tools struct{}

func init() { Register("tools", func(Device, Credential) (Driver, error) { return tools{}, nil }) }

// ToolPrograms are the programs the tools use.
var ToolPrograms = []string{"ping", "mtr", "nmap", "dig", "curl"}

func (tools) Facts(context.Context) (Facts, error) {
	var have, miss []string
	for _, p := range ToolPrograms {
		if _, err := exec.LookPath(p); err == nil {
			have = append(have, p)
		} else {
			miss = append(miss, p)
		}
	}
	h, _ := os.Hostname()
	f := Facts{Hostname: h, Vendor: "netdir", Model: "Network tools", OSVersion: strings.Join(have, " ") + " (and whois)"}
	if len(have) == 0 {
		return f, errors.New("none of the programs is installed: ping, mtr, nmap, dig, curl")
	}
	if len(miss) > 0 {
		f.OSVersion += "; missing " + strings.Join(miss, " ")
	}
	return f, nil
}

func (tools) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (tools) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (tools) Config(context.Context) (string, error)          { return "", ErrUnsupported }
func (tools) Show(context.Context, string) (string, error) {
	return "", errors.New("the tools are used with net_ping, net_mtr, net_dig, net_curl, net_whois and net_scan, naming a gateway they are enabled on")
}
func (tools) Close(context.Context) {}

// RawChange: nothing here to change.
func (tools) RawChange(context.Context, Raw, bool) (RawResult, error) {
	return RawResult{}, errors.New("the network tools are not changed")
}
