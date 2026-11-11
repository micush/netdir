package device

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Select picks the devices a request is for.  target is a comma-separated list of terms, a device being picked when any
// term matches it:
//
//	all            every device that is not disabled
//	NAME           the device of that name (case does not matter); a disabled one too, so it can be asked on purpose
//	tag:T          the devices with tag T ("tag:site=dc1", "tag:edge")
//	platform:P     the devices of platform P ("platform:nxos")
//
// A term that matches nothing is an error, so a typo is never quietly a smaller request.
func Select(devs []Device, target string) ([]Device, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New(`no target: a device name, tag:TAG, platform:PLATFORM, or "all"`)
	}
	picked := map[string]bool{}
	for _, term := range strings.Split(target, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		hit := false
		for _, d := range devs {
			var m bool
			switch {
			case strings.EqualFold(term, "all"):
				m = !d.Disabled
			case strings.HasPrefix(term, "tag:"):
				m = !d.Disabled && hasTag(d, term[4:])
			case strings.HasPrefix(term, "platform:"):
				m = !d.Disabled && strings.EqualFold(d.Platform, term[9:])
			default:
				m = strings.EqualFold(d.Name, term)
			}
			if m {
				picked[d.Name], hit = true, true
			}
		}
		if !hit {
			return nil, fmt.Errorf("target %q matches no device", term)
		}
	}
	var out []Device
	for _, d := range devs {
		if picked[d.Name] {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func hasTag(d Device, t string) bool {
	for _, x := range d.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Result is one device's answer to a request that went to several.
type Result struct {
	Device   string `json:"device"`
	Platform string `json:"platform"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Data     any    `json:"data,omitempty"`
	MS       int64  `json:"ms"`
	// Reused says that the answer came over a driver kept open from an earlier request (FanoutReuse): no new login.
	Reused bool `json:"reused,omitempty"`
	// CachedSecs: the answer is what the device said this many seconds ago (the gateway's short answer cache), not asked just now.
	CachedSecs *int `json:"cached_s,omitempty"`
	// FromMonitor: the facts are those the health monitor collected in the background, not asked for this read.
	FromMonitor bool `json:"from_monitor,omitempty"`
}

// Fanout runs fn against every device in devs, at most par at a time, each with its own time limit, and returns one
// Result per device in the order of devs.  A device's driver is opened before fn and closed after it.
func Fanout(ctx context.Context, devs []Device, creds []Credential, par int, each time.Duration, fn func(context.Context, Driver) (any, error)) []Result {
	return fanout(ctx, devs, creds, par, each, fn, one)
}

// fanout is Fanout with the way one device is asked: with a driver of its own (one) or with one that is kept (oneReuse).
func fanout(ctx context.Context, devs []Device, creds []Credential, par int, each time.Duration, fn func(context.Context, Driver) (any, error),
	ask func(context.Context, Device, map[string]Credential, time.Duration, func(context.Context, Driver) (any, error)) Result) []Result {
	if par < 1 {
		par = 1
	}
	cred := map[string]Credential{}
	for _, c := range creds {
		cred[c.Name] = c
	}
	out := make([]Result, len(devs))
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, d := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = Result{Device: d.Name, Platform: d.Platform, Error: ctx.Err().Error()}
				return
			}
			defer func() { <-sem }()
			out[i] = ask(ctx, d, cred, each, fn)
		}()
	}
	wg.Wait()
	return out
}

func one(ctx context.Context, d Device, cred map[string]Credential, each time.Duration, fn func(context.Context, Driver) (any, error)) (r Result) {
	start := time.Now()
	r = Result{Device: d.Name, Platform: d.Platform}
	defer func() {
		if p := recover(); p != nil { // a driver bug costs that device's answer, not the gateway
			r.OK, r.Data, r.Error = false, nil, fmt.Sprintf("driver failure: %v", p)
		}
		r.MS = time.Since(start).Milliseconds()
	}()
	c, ok := cred[d.Credential]
	if d.Platform == "tools" {
		ok = true // no login
	}
	if !ok {
		r.Error = fmt.Sprintf("credential %q is not in the credentials list", d.Credential)
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, each)
	defer cancel()
	drv, err := Open(d, c)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer drv.Close(context.WithoutCancel(ctx))
	v, err := fn(ctx, drv)
	if err != nil {
		r.Error = scrub(err.Error(), c)
		return r
	}
	r.OK, r.Data = true, v
	return r
}

// scrub takes a credential's secrets out of a message, in case a device or a library echoed one back.
func scrub(msg string, c Credential) string {
	for _, s := range []string{c.Password, c.Token} {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "(hidden)")
		}
	}
	return msg
}

// showRE is what a read-only command looks like: "show" and words, and at most an output filter.
var showRE = regexp.MustCompile(`^show(\s+[^\s|;<>&` + "`" + `$]+)+(\s*\|\s*(include|exclude|begin|section|count|json|json-pretty|xml|grep|egrep|head|last|no-more|match|except|find|display|trim|resolve)(\s+[^|;<>&` + "`" + `$]+)?)*\s*$`)

// CheckShow refuses anything but a single read-only command: it must start with "show", be one line, and may end in
// output filters (| include X, | json, ...) but never one that writes (| tee, | redirect, | save, > file), nor chain a
// second command (;).  Every platform's show is checked here, whatever its own rules.
func CheckShow(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", errors.New("no command")
	}
	if len(cmd) > 512 {
		return "", errors.New("the command is longer than 512 characters")
	}
	if strings.ContainsAny(cmd, "\r\n\x00") {
		return "", errors.New("one command, on one line")
	}
	if !showRE.MatchString(cmd) {
		return "", fmt.Errorf("%q is refused: only a \"show ...\" command, optionally with | include, exclude, begin, section, count or json; no ; or redirection", cmd)
	}
	return cmd, nil
}
