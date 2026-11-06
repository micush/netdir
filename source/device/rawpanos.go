package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PAN-OS and Panorama: one XML API "config" action.  Method is the action (set, edit, delete, rename, move), Path the XPath
// (below /config/), Body the element for set and edit (XML), the new name for rename, and "where=top&dst=name" for move.
// A change goes to the candidate configuration; Save commits it.  The answer to a failed action changed nothing; what was at the
// path before is returned (Before) so that it can be set again, but this program does not do that by itself.

func (p *panos) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	act := strings.ToLower(strings.TrimSpace(r.Method))
	switch act {
	case "set", "edit", "delete", "rename", "move":
	default:
		return res, fmt.Errorf("method %q: use set, edit, delete, rename or move", r.Method)
	}
	if len(r.Lines) > 0 {
		return res, errors.New("lines: PAN-OS is changed with an action, an XPath and an element")
	}
	x := r.Path
	if !strings.HasPrefix(x, "/config/") || len(x) > 2000 || strings.Contains(x, "\x00") || strings.Contains(strings.ToLower(x), "mgt-config") {
		return res, errors.New("path: an XPath below /config/ (the management users and keys under mgt-config are not changed here)")
	}
	if len(r.Body) > rawMaxBody {
		return res, errors.New("body: larger than 256 KB")
	}
	q := url.Values{"type": {"config"}, "action": {act}, "xpath": {x}}
	switch act {
	case "set", "edit":
		if !strings.HasPrefix(strings.TrimSpace(r.Body), "<") {
			return res, errors.New("body: the XML element to " + act)
		}
		q.Set("element", r.Body)
	case "rename":
		if !panNameRE.MatchString(r.Body) {
			return res, errors.New("body: the new name")
		}
		q.Set("newname", r.Body)
	case "move":
		m, err := url.ParseQuery(r.Body)
		if err != nil || m.Get("where") == "" {
			return res, errors.New("body: where=top|bottom|before|after (and dst=<name> for before and after)")
		}
		q.Set("where", m.Get("where"))
		if m.Get("dst") != "" {
			q.Set("dst", m.Get("dst"))
		}
	}
	if act != "set" {
		if b, err := p.fetch(ctx, url.Values{"type": {"config"}, "action": {"get"}, "xpath": {x}}); err == nil {
			if v, err := panResult(b); err == nil && v != nil {
				j, _ := json.Marshal(Redact(v))
				res.Before = rawTrunc(j)
			}
		}
	}
	if dry {
		res.Note = fmt.Sprintf("would send %s %s to the candidate configuration; nothing was changed", act, x)
		return res, nil
	}
	b, err := p.fetch(ctx, q)
	if err != nil {
		return res, fmt.Errorf("%s %s: %w", act, x, err)
	}
	if _, err := panResult(b); err != nil {
		return res, fmt.Errorf("%s %s: %w", act, x, err)
	}
	res.Applied = true
	res.Answer = rawTrunc(b)
	if r.Save {
		cb, err := p.fetch(ctx, url.Values{"type": {"commit"}, "cmd": {"<commit></commit>"}})
		if err == nil {
			_, err = panResult(cb)
		}
		if err != nil {
			res.Note = "the change is in the candidate configuration; committing failed"
			return res, fmt.Errorf("commit: %w", err)
		}
		res.Saved = true
		res.Note = "committed (PAN-OS commits as a job: check it in the device's job list)"
	} else {
		res.Note = "the change is in the candidate configuration and is not active until it is committed"
	}
	return res, nil
}
