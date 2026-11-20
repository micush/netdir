package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// FlowDirector (platform "flowdir"): the clustered NetFlow, IPFIX and sFlow collector, reached through its own MCP endpoint
// (POST /mcp on its GUI port, 19996, JSON answers).
//
// The credential is an MCP key as the token ("Authorization: Bearer KEY", made under Configure ▸ Monitoring ▸ MCP ▸ Keys of
// that FlowDirector).  FlowDirector only reads, so the key's ro or rw makes no difference.  The driver only calls FlowDirector's
// tools: list_nodes (Facts), get_topology, flow_top (the biggest conversations, hosts, services ... over a range), flow_timeseries
// (traffic over time), flow_exporters (who is sending) and flow_status (the collectors' counters and storage).  A cluster
// answers for all its nodes, so any node's address will do.  FlowDirector hides its own secrets in every answer.
//
// It is not a network device: no interfaces, neighbors, ports or routes, no configuration to read (ErrUnsupported), and nothing
// that changes it (RawChange refuses).

func init() {
	Register("flowdir", func(d Device, c Credential) (Driver, error) { return newFlowdir(d, c) })
}

type flowdir struct {
	d   Device
	dir *director // the transport: one MCP tool call, its answer as JSON (kind "flow", no node option)
}

func newFlowdir(d Device, c Credential) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: FlowDirector needs an MCP key as the credential's token (Configure ▸ Monitoring ▸ MCP ▸ Keys on FlowDirector)", d.Name)
	}
	api, err := newAPIClient(d, 19996)
	if err != nil {
		return nil, err
	}
	api.hdr.Set("Authorization", "Bearer "+c.Token)
	return &flowdir{d: d, dir: &director{d: d, api: api, kind: "flow"}}, nil
}

func (m *flowdir) Close(context.Context) { m.dir.api.close() }

// call runs one tool (callPlain: FlowDirector's tools take no node) with an object for arguments, never null.
func (m *flowdir) call(ctx context.Context, tool string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	return m.dir.callPlain(ctx, tool, args)
}

func (m *flowdir) Facts(ctx context.Context) (Facts, error) {
	v, err := m.call(ctx, "list_nodes", nil)
	if err != nil {
		return Facts{}, err
	}
	nodes := rows(v)
	f := Facts{Vendor: "FlowDirector", Model: fmt.Sprintf("flow collector, %d node(s)", len(nodes))}
	var pick map[string]any
	for _, n := range nodes {
		if boolv(n["this_node"]) {
			pick = n
		}
	}
	if pick == nil && len(nodes) > 0 {
		pick = nodes[0]
	}
	if pick != nil {
		f.Hostname = str(pick["name"])
		if ver := str(pick["version"]); ver != "" {
			f.OSVersion = "v" + ver
		}
	}
	return f, nil
}

func (m *flowdir) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (m *flowdir) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (m *flowdir) Config(context.Context) (string, error)          { return "", ErrUnsupported }

// RawChange: FlowDirector is only read here.
func (m *flowdir) RawChange(context.Context, Raw, bool) (RawResult, error) {
	return RawResult{}, errors.New("FlowDirector is only read here: its flows, exporters and settings are not changed")
}

// ---- show <name> [key=value ...]: the read tools ----

var flowdirShow = map[string]string{
	"nodes": "list_nodes", "topology": "get_topology", "exporters": "flow_exporters", "status": "flow_status",
	"top": "flow_top", "timeseries": "flow_timeseries",
}

var flowdirGroupings = []string{"conversation", "flow", "src", "dst", "host", "service", "protocol", "exporter", "interface", "src_as", "dst_as"}

var (
	flowdirRangeRE = regexp.MustCompile(`^([0-9]{1,4}[mhdwy]|all)$`)
	flowdirStepRE  = regexp.MustCompile(`^[0-9]{1,4}[mhd]$`)
	flowdirTimeRE  = regexp.MustCompile(`^[0-9TZtz:+.\-]{1,40}$`)
)

// flowdirArgs are the keys of show top and show timeseries; the kind says how a value is checked.
var flowdirArgs = map[string]string{
	"by": "by", "step": "step", "range": "range", "from": "time", "to": "time", "metric": "metric", "limit": "limit", "dedupe": "dedupe",
	"exporter": "text", "host": "text", "src": "text", "dst": "text", "port": "text", "proto": "text", "interface": "text", "as": "text", "filter": "text",
}

// flowdirTokens splits "key=value key="a value with spaces"" into its words; a value may be in double quotes.
func flowdirTokens(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, started := false, false
	for _, r := range s {
		switch {
		case r == '"':
			in, started = !in, true
		case (r == ' ' || r == '\t') && !in:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if in {
		return nil, errors.New(`a " is not closed`)
	}
	if started {
		out = append(out, cur.String())
	}
	return out, nil
}

func flowdirNames() []string {
	var n []string
	for k := range flowdirShow {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Show takes "show NAME [key=value ...]": NAME is nodes, topology, exporters, status, top or timeseries.  top and timeseries
// take by (conversation, flow, src, dst, host, service, protocol, exporter, interface, src_as, dst_as), range (15m, 1h, 6h, 1d, 7d,
// 30d, 90d, 1y or all) or from and to, metric (bytes, packets, flows), limit (1 to 1000), dedupe (on or off), step (timeseries: 1m,
// 5m, 1h ...), the narrowing keys exporter, host, src, dst, port, proto, interface and as, and filter, a filter with AND, OR, NOT
// and wildcards in double quotes: show top by=conversation range=1d filter="host=10.1.*.* AND !port=53".
func (m *flowdir) Show(ctx context.Context, cmd string) (string, error) {
	w, err := flowdirTokens(cmd)
	usage := `show NAME [key=value ...], e.g. show top by=host range=1d filter="host=10.1.*.* AND !port=53"; names: ` + strings.Join(flowdirNames(), ", ")
	if err != nil || len(w) < 2 || !strings.EqualFold(w[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(usage)
	}
	name := strings.ToLower(w[1])
	tool, ok := flowdirShow[name]
	if !ok {
		return "", fmt.Errorf("show %s: not a read FlowDirector has; names: %s", w[1], strings.Join(flowdirNames(), ", "))
	}
	args := map[string]any{}
	if tool != "flow_top" && tool != "flow_timeseries" && len(w) > 2 {
		return "", fmt.Errorf("show %s takes no arguments", name)
	}
	for _, kv := range w[2:] {
		k, v, ok := strings.Cut(kv, "=")
		kind := flowdirArgs[k]
		if !ok || kind == "" || (k == "step" && tool != "flow_timeseries") {
			return "", fmt.Errorf("%q: use key=value with a key of by, range, from, to, metric, limit, dedupe, exporter, host, src, dst, port, proto, interface, as, filter (and step for timeseries)", kv)
		}
		if err := flowdirCheck(k, kind, v); err != nil {
			return "", err
		}
		if kind == "limit" {
			n, _ := strconv.Atoi(v)
			args[k] = n
		} else {
			args[k] = v
		}
	}
	v, err := m.call(ctx, tool, args)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

func flowdirCheck(k, kind, v string) error {
	switch kind {
	case "by":
		for _, g := range flowdirGroupings {
			if v == g {
				return nil
			}
		}
		return fmt.Errorf("by=%s: one of %s", v, strings.Join(flowdirGroupings, ", "))
	case "metric":
		if v != "bytes" && v != "packets" && v != "flows" {
			return errors.New("metric=: bytes, packets or flows")
		}
	case "dedupe":
		if v != "on" && v != "off" {
			return errors.New("dedupe=: on or off")
		}
	case "limit":
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1000 {
			return errors.New("limit=N: a number from 1 to 1000")
		}
	case "range":
		if !flowdirRangeRE.MatchString(v) {
			return errors.New("range=: 15m, 1h, 6h, 1d, 7d, 30d, 90d, 1y or all")
		}
	case "step":
		if !flowdirStepRE.MatchString(v) {
			return errors.New("step=: 1m, 5m, 1h ...")
		}
	case "time":
		if !flowdirTimeRE.MatchString(v) {
			return fmt.Errorf("%s=: unix seconds or an RFC 3339 time", k)
		}
	default:
		if v == "" || len(v) > 1000 || ctlRE2.MatchString(v) {
			return fmt.Errorf("%s=: a value of up to 1000 characters, no control characters", k)
		}
	}
	return nil
}

// ctlRE2 is a control character (a space is fine in a quoted filter).
var ctlRE2 = regexp.MustCompile(`[\x00-\x1f\x7f]`)
