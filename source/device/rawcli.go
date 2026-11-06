package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Arista EOS and Cisco NX-OS take lines of configuration.

func randHex() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ---- Arista EOS: a configuration session with a commit timer ----

// What a change does not send: leaving or ending the session, reload, erase, file and shell commands, and anything that turns
// off eAPI or touches the management interface (the switch would stop answering).
var eosRawDeny = regexp.MustCompile(`^(reload|write|erase|delete|format|copy|bash|python|run|guestshell|install|configure|enable|end|commit|abort|` +
	`no\s+management\s+api\s+http-commands|interface\s+management|interface\s+ma)`)

const eosConfirmWindow = "00:03:00"

func (e *eos) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if cmd, ok := rebootLine(r.Lines); ok && r.Method == "" && r.Path == "" && r.Body == "" {
		return e.reload(ctx, cmd, r.Save, dry)
	}
	lines, err := checkLines(r, eosRawDeny)
	if err != nil {
		return res, err
	}
	id, err := randHex()
	if err != nil {
		return res, err
	}
	sess := "netdir" + id
	open := "configure session " + sess
	if dry {
		cmds := append(append([]string{open}, lines...), "show session-config diffs", "abort")
		a, err := e.post(ctx, cmds, "text")
		if err != nil {
			e.abort(ctx, sess)
			return res, err
		}
		if n := len(a.Result); n >= 2 {
			if m, ok := a.Result[n-2].(map[string]any); ok {
				res.Before = rawTrunc([]byte(str(m["output"])))
			}
		}
		res.Note = "Before is the switch's own diff of the session; nothing was committed"
		return res, nil
	}
	cmds := append(append([]string{open}, lines...), "commit timer "+eosConfirmWindow)
	if _, err := e.post(ctx, cmds, "json"); err != nil {
		e.abort(ctx, sess)
		return res, fmt.Errorf("the switch refused the change (nothing was committed): %w", err)
	}
	res.Applied = true
	// the change is live for three minutes; the switch undoes it by itself unless it is confirmed
	if _, err := e.post(ctx, []string{"show version"}, "json"); err != nil {
		res.Note = "the change was committed with a " + eosConfirmWindow + " timer, but the switch did not answer afterwards: it undoes the change by itself when the timer runs out"
		return res, fmt.Errorf("the switch did not answer after the change: %w", err)
	}
	if _, err := e.post(ctx, []string{open, "commit"}, "json"); err != nil {
		res.Note = "the switch answered, but confirming the commit failed: the change is undone when the timer runs out"
		return res, fmt.Errorf("confirming the commit: %w", err)
	}
	if r.Save {
		if _, err := e.post(ctx, []string{"write memory"}, "json"); err != nil {
			return res, fmt.Errorf("the change is applied but saving it failed: %w", err)
		}
		res.Saved = true
	}
	return res, nil
}

func (e *eos) abort(ctx context.Context, sess string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_, _ = e.post(actx, []string{"configure session " + sess, "abort"}, "json")
}

// ---- Cisco NX-OS: NX-API cli_conf with a checkpoint ----

var nxosRawDeny = regexp.MustCompile(`^(reload|write|erase|delete|format|copy|bash|python|run|guestshell|install|configure|end|` +
	`no\s+feature\s+(nxapi|restconf)|no\s+nxapi|interface\s+mgmt)`)

// nxSend sends one NX-API request of type cli_conf or cli_show_ascii, and checks the answer of every command in it.
func (x *nxos) nxSend(ctx context.Context, typ string, cmds []string) error {
	if typ != "cli_conf" && typ != "cli_show_ascii" {
		return fmt.Errorf("NX-API: a request of type %q is never sent", typ)
	}
	req := map[string]any{"ins_api": map[string]any{"version": "1.0", "type": typ, "chunk": "0", "sid": "1",
		"input": strings.Join(cmds, " ;"), "output_format": "json"}}
	b, err := x.api.do(ctx, http.MethodPost, "/ins", req, nil)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("NX-API: the answer is not JSON: %v", err)
	}
	ins, _ := m["ins_api"].(map[string]any)
	outs, _ := ins["outputs"].(map[string]any)
	for _, o := range rows(outs["output"]) {
		if code := str(o["code"]); code != "200" {
			msg := firstOf(strings.TrimSpace(str(o["msg"])), "the command failed")
			return &nxError{se: &statusError{Code: http.StatusBadRequest, Body: msg}, cmd: str(o["input"]), msg: msg}
		}
	}
	return nil
}

func (x *nxos) RawChange(ctx context.Context, r Raw, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if cmd, ok := rebootLine(r.Lines); ok && r.Method == "" && r.Path == "" && r.Body == "" {
		return x.reload(ctx, cmd, r.Save, dry)
	}
	lines, err := checkLines(r, nxosRawDeny)
	if err != nil {
		return res, err
	}
	if dry {
		res.Before = strings.Join(lines, "\n")
		res.Note = "NX-OS cannot preview a change: these lines would be sent after a checkpoint is taken; nothing was changed"
		return res, nil
	}
	id, err := randHex()
	if err != nil {
		return res, err
	}
	cp := "netdir" + id
	if err := x.nxSend(ctx, "cli_show_ascii", []string{"checkpoint " + cp}); err != nil {
		return res, fmt.Errorf("the checkpoint could not be taken (nothing was changed): %w", err)
	}
	drop := func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = x.nxSend(dctx, "cli_show_ascii", []string{"no checkpoint " + cp})
	}
	defer drop()
	back := func(why error) (RawResult, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		if err := x.nxSend(rctx, "cli_show_ascii", []string{"rollback running-config checkpoint " + cp}); err != nil {
			res.Note = "rolling back to the checkpoint failed: " + err.Error()
		} else {
			res.RolledBack = true
		}
		return res, why
	}
	if err := x.nxSend(ctx, "cli_conf", lines); err != nil {
		// lines before the refused one were applied: NX-OS has no all-or-nothing session
		return back(fmt.Errorf("the switch refused a line: %w", err))
	}
	res.Applied = true
	if _, err := x.get(ctx, "show version"); err != nil {
		return back(fmt.Errorf("the switch did not answer after the change: %w", err))
	}
	if r.Save {
		if err := x.nxSend(ctx, "cli_show_ascii", []string{"copy running-config startup-config"}); err != nil {
			return res, fmt.Errorf("the change is applied but saving it failed: %w", err)
		}
		res.Saved = true
	}
	return res, nil
}

// reload restarts the switch: the one command, sent alone (no session, no timer, nothing read afterwards).  Save writes the
// configuration first.
func (e *eos) reload(ctx context.Context, cmd string, save, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if dry {
		res.Note = "would send " + cmd + "; nothing was changed"
		return res, nil
	}
	if save {
		if _, err := e.post(ctx, []string{"write memory"}, "json"); err != nil {
			return res, fmt.Errorf("saving the configuration before the restart failed (nothing was restarted): %w", err)
		}
		res.Saved = true
	}
	if _, err := e.post(ctx, []string{cmd}, "json"); err != nil && !connEnded(err) {
		return res, fmt.Errorf("the switch refused the restart: %w", err)
	}
	res.Applied, res.Note = true, rebootNote
	return res, nil
}

// reload restarts the switch (terminal dont-ask, so that it does not wait for a confirmation).
func (x *nxos) reload(ctx context.Context, cmd string, save, dry bool) (RawResult, error) {
	res := RawResult{DryRun: dry}
	if dry {
		res.Note = "would send " + cmd + "; nothing was changed"
		return res, nil
	}
	if save {
		if err := x.nxSend(ctx, "cli_show_ascii", []string{"copy running-config startup-config"}); err != nil {
			return res, fmt.Errorf("saving the configuration before the restart failed (nothing was restarted): %w", err)
		}
		res.Saved = true
	}
	if err := x.nxSend(ctx, "cli_show_ascii", []string{"terminal dont-ask", "reload"}); err != nil && !connEnded(err) {
		return res, fmt.Errorf("the switch refused the restart: %w", err)
	}
	res.Applied, res.Note = true, rebootNote
	return res, nil
}
