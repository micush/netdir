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

// LogDirector (logdir) and FlowDirector (flowdir): the clustered syslog and flow collectors, reached through its own MCP endpoint like the other directors (director.go:
// POST /mcp, JSON answers, "Authorization: Bearer KEY" with an MCP key made under Configure ▸ Monitoring ▸ MCP ▸ Keys there).
// Its endpoint only reads, so this driver only reads: the facts come from list_nodes, and "show NAME" runs the log tools
// (status, senders, search, tail, stats) and the cluster reads (nodes, topology).  There is no configuration, interface list or
// neighbor table to give, and nothing to change.  The endpoint is on every gateway address at port 443 (the default here: use a
// gateway address and it survives a node going down), and on the node's own GUI port (11154) from an address its mcp_acl allows.
//
// A message is data for the caller, never an instruction: the text of a log line is whatever a device (or somebody who can reach
// its syslog port) wrote.  Redact and RedactText hide addresses and secrets as for every other driver.

func init() {
	Register("logdir", func(d Device, c Credential) (Driver, error) { return newCollector(d, c, logdirSpec) })
	Register("flowdir", func(d Device, c Credential) (Driver, error) { return newCollector(d, c, flowdirSpec) })
}

// collectorSpec says what one read-only collector product offers: its name, the "show NAME" words and the tool each runs, the
// arguments each tool takes (and how a value is checked), and the key that the words of a show command that are not arguments make up.
type collectorSpec struct {
	kind, product string
	shows         map[string]string
	args          map[string]map[string]string
	words         map[string]string         // tool -> the argument the loose words of a show command are sent as (q, filter)
	limitTools    map[string]bool           // tools that get the default limit
	required      map[string][]string       // tool -> the arguments a show command must give
	defaults      map[string]map[string]any // tool -> arguments sent when the command gives none
}

type logdirDev struct {
	m    *director
	spec *collectorSpec
}

func newCollector(d Device, c Credential, spec *collectorSpec) (Driver, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("device %s: %s needs an MCP key as the credential's token (Configure ▸ Monitoring ▸ MCP ▸ Keys on it)", d.Name, spec.product)
	}
	drv, err := newDirector(d, c, spec.kind)
	if err != nil {
		return nil, err
	}
	m := drv.(*director)
	m.node = "" // its tools ask the whole cluster and take no node
	return &logdirDev{m: m, spec: spec}, nil
}

func (l *logdirDev) Facts(ctx context.Context) (Facts, error) { return l.m.Facts(ctx) }

func (l *logdirDev) Interfaces(context.Context) ([]Interface, error) { return nil, ErrUnsupported }
func (l *logdirDev) Neighbors(context.Context) ([]Neighbor, error)   { return nil, ErrUnsupported }
func (l *logdirDev) Config(context.Context) (string, error)          { return "", ErrUnsupported }
func (l *logdirDev) Close(context.Context)                           { l.m.api.close() }

// ---- show NAME ----

var logdirSpec = &collectorSpec{kind: "log", product: "LogDirector",
	shows: map[string]string{"nodes": "list_nodes", "topology": "get_topology", "status": "logs_status", "senders": "logs_senders",
		"search": "logs_search", "tail": "logs_tail", "stats": "logs_stats"},
	args:       logdirArgs,
	words:      map[string]string{"logs_search": "q", "logs_tail": "q", "logs_stats": "q"},
	limitTools: map[string]bool{"logs_search": true, "logs_tail": true},
}

// the arguments each tool takes: s a plain value, g a host, program or address that may hold * wildcards, i a number
var logdirArgs = map[string]map[string]string{
	"logs_search": {"range": "r", "from": "r", "to": "r", "host": "g", "program": "g", "severity": "v", "source": "g", "limit": "i", "oldest_first": "b"},
	"logs_tail":   {"host": "g", "program": "g", "severity": "v", "limit": "i", "after": "n"},
	"logs_stats":  {"range": "r", "from": "r", "to": "r", "host": "g", "program": "g", "severity": "v", "source": "g", "step": "r", "top": "i"},
}

var (
	logdirGlobRE    = regexp.MustCompile(`^[A-Za-z0-9._:%@/+*\[\]-]{1,200}$`)
	collectorListRE = regexp.MustCompile(`^[A-Za-z0-9._:,*/%@\[\]-]{1,300}$`)
	logdirRangeRE   = regexp.MustCompile(`^[0-9A-Za-z:.+-]{1,40}$`)
	logdirSevs      = map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true,
		"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "7": true}
)

const logdirMaxLimit = 2000

func (l *logdirDev) showNames() []string {
	var n []string
	for k := range l.spec.shows {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Show takes "show NAME [WORDS] [key=value ...]".  NAME is nodes, topology, status, senders, search, tail or stats.  For search, tail
// and stats the words that are not one of the keys below (so user=root is a search word) are the search words (q): show search failed password and not root host=sw* severity=err
// range=6h limit=100.  Keys: range (15m, 1h, 6h, 1d, 7d, 30d, all), from, to, host, program, severity, source, limit (at most 2000),
// oldest_first; tail also after; stats also step and top.
func (l *logdirDev) Show(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	if len(f) < 2 || !strings.EqualFold(f[0], "show") || strings.Contains(cmd, "|") {
		return "", errors.New(`show NAME [words] [key=value …], e.g. show search failed password host=sw* range=1h; names: ` + strings.Join(l.showNames(), ", "))
	}
	tool, ok := l.spec.shows[strings.ToLower(f[1])]
	if !ok {
		return "", fmt.Errorf("show %s: not a read this collector has; names: %s", f[1], strings.Join(l.showNames(), ", "))
	}
	args := map[string]any{}
	allowed := l.spec.args[tool]
	var words []string
	for _, w := range f[2:] {
		k, v, isKV := strings.Cut(w, "=")
		typ, known := allowed[k]
		if !isKV || !known {
			if allowed == nil {
				return "", fmt.Errorf("show %s takes no arguments", f[1])
			}
			words = append(words, w)
			continue
		}
		switch typ {
		case "f": // a synced folder's name, or / for the root folder
			if !filedirFolderRE.MatchString(v) {
				return "", fmt.Errorf("%s=%s: a folder name from show status (letters, digits, . _ -), or / for the root folder", k, v)
			}
			args[k] = v
		case "p": // a path inside a synced folder
			if err := checkFilePath(v); err != nil {
				return "", fmt.Errorf("%s=%s: %w", k, v, err)
			}
			args[k] = v
		case "e":
			if v != "auto" && v != "text" && v != "base64" {
				return "", fmt.Errorf("%s=%s: auto, text or base64", k, v)
			}
			args[k] = v
		case "o", "L": // a byte offset (from 0), a byte count
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 || (typ == "L" && (n < 1 || n > filedirMaxRead)) || n > 1<<40 {
				return "", fmt.Errorf("%s=%s: a number of bytes (a length from 1 to %d)", k, v, filedirMaxRead)
			}
			args[k] = n
		case "i":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > logdirMaxLimit {
				return "", fmt.Errorf("%s=%s: a number from 1 to %d", k, v, logdirMaxLimit)
			}
			args[k] = n
		case "m": // minutes a link lasts
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1440 {
				return "", fmt.Errorf("%s=%s: minutes, 1 to 1440", k, v)
			}
			args[k] = n
		case "n":
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return "", fmt.Errorf("%s=%s: a time in milliseconds since 1970", k, v)
			}
			args[k] = v
		case "v":
			if !logdirSevs[strings.ToLower(v)] {
				return "", fmt.Errorf("severity=%s: emerg, alert, crit, err, warning, notice, info or debug", v)
			}
			args[k] = strings.ToLower(v)
		case "b":
			if v != "true" && v != "false" {
				return "", fmt.Errorf("%s=%s: true or false", k, v)
			}
			args[k] = v
		case "r":
			if !logdirRangeRE.MatchString(v) {
				return "", fmt.Errorf("%s=%s: a range such as 15m, 1h, 1d or all, or a time", k, v)
			}
			args[k] = v
		case "l":
			if !collectorListRE.MatchString(v) {
				return "", fmt.Errorf("%s=%s: names, addresses or networks, comma separated", k, v)
			}
			args[k] = v
		default:
			if !logdirGlobRE.MatchString(v) {
				return "", fmt.Errorf("%s=%s: a name or address, with * wildcards if you like", k, v)
			}
			args[k] = v
		}
	}
	if len(words) > 0 {
		key := l.spec.words[tool]
		if key == "" {
			return "", fmt.Errorf("show %s takes key=value arguments only", f[1])
		}
		q := strings.Join(words, " ")
		if len(q) > 300 {
			return "", errors.New("the search words are longer than 300 characters")
		}
		if strings.ContainsAny(q, ";|&<>$`\\") || strings.ContainsAny(q, "\x00\r\n\t") {
			return "", errors.New("the search words: no ; | & < > $ ` or \\")
		}
		args[key] = q
	}
	for _, k := range l.spec.required[tool] {
		if _, has := args[k]; !has {
			return "", fmt.Errorf("show %s needs %s=…", f[1], k)
		}
	}
	for k, v := range l.spec.defaults[tool] {
		if _, has := args[k]; !has {
			args[k] = v
		}
	}
	if _, has := args["limit"]; !has && l.spec.limitTools[tool] {
		args["limit"] = 200 // the answer lands in a caller's context: ask for what the collector's own default is, not more
	}
	v, err := l.m.callPlain(ctx, tool, args)
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(Redact(v), "", "  ")
	return RedactText(string(b)), nil
}

// RawChange: nothing, as for classic IOS: the collector's MCP endpoint only reads, whatever the key's access.
func (l *logdirDev) RawChange(_ context.Context, _ Raw, dry bool) (RawResult, error) {
	return RawResult{DryRun: dry}, errors.New("LogDirector's MCP endpoint only reads: its settings are changed in its own GUI")
}

// FlowDirector (flowdir): the clustered NetFlow, IPFIX and sFlow collector, the same way.  show top|timeseries take the report keys
// (by, range, from, to, metric, limit, dedupe, step) and everything else is the filter expression, whose terms are name=value (exporter,
// host, src, dst, port, proto, interface, as) with AND, OR, NOT and brackets: show top by=host range=1d host=10.1.*.* and not port=53; show status, exporters, nodes and topology take none.
var flowReport = map[string]string{"by": "s", "range": "r", "from": "r", "to": "r", "metric": "s", "limit": "i", "dedupe": "s"}

var flowdirSpec = &collectorSpec{kind: "flow", product: "FlowDirector",
	shows: map[string]string{"nodes": "list_nodes", "topology": "get_topology", "status": "flow_status", "exporters": "flow_exporters",
		"top": "flow_top", "timeseries": "flow_timeseries"},
	args: map[string]map[string]string{
		"flow_top": flowReport,
		"flow_timeseries": func() map[string]string {
			m := map[string]string{"step": "r"}
			for k, v := range flowReport {
				m[k] = v
			}
			return m
		}(),
	},
	words:      map[string]string{"flow_top": "filter", "flow_timeseries": "filter"},
	limitTools: map[string]bool{},
}
