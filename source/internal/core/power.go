package core

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Power: restart or shut down the host this daemon runs on, now or later.
//
// The scheduling itself is left to shutdown(8) (and so survives a restart of
// netdir and can be cancelled with shutdown -c; a minute before it fires the primary role is handed over, see powerHandoverTick).  An immediate action waits a
// moment so the HTTP/CLI reply gets out first.  Unlike the parapet page this
// came from, an immediate action asks the same question an update does — would
// a gateway lose its last serving member? — and refuses unless forced.

// PowerReq is one request.
type PowerReq struct {
	Action  string `json:"action"`  // restart | shutdown | cancel
	When    string `json:"when"`    // now | in | at   (default now)
	Minutes int    `json:"minutes"` // for "in"
	Time    string `json:"time"`    // for "at": 24-hour HH:MM
	Force   bool   `json:"force"`   // go ahead although a gateway would be left unserved
}

// PowerResult is what a request did.
type PowerResult struct {
	Action string `json:"action"`
	When   string `json:"when"`
}

// PowerPending describes a shutdown/reboot that is already scheduled.
type PowerPending struct {
	Scheduled bool   `json:"scheduled"`
	Action    string `json:"action,omitempty"` // restart | shutdown
	At        string `json:"at,omitempty"`     // RFC 3339
}

const MaxPowerMinutes = 60 * 24 * 7

var (
	// powerRun runs a command (replaceable in tests).
	PowerRun = func(name string, args ...string) error { return exec.Command(name, args...).Run() }
	// powerStart starts one detached (replaceable in tests).
	PowerStart = func(name string, args ...string) error { return exec.Command(name, args...).Start() }
	// powerScheduledFile is where systemd records a scheduled shutdown.
	PowerScheduledFile = "/run/systemd/shutdown/scheduled"
	// powerDelay is how long an immediate action waits so the reply gets out.
	PowerDelay = 800 * time.Millisecond
	// powerHandoverLead is how long before a scheduled restart or shut down the primary role is handed to another member.
	PowerHandoverLead = time.Minute
)

func ValidHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	h, m := int(s[0]-'0')*10+int(s[1]-'0'), int(s[3]-'0')*10+int(s[4]-'0')
	return h < 24 && m < 60
}

func ReadPowerPending(path string) PowerPending {
	b, err := os.ReadFile(path)
	if err != nil {
		return PowerPending{}
	}
	var usec int64
	mode := ""
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		switch k {
		case "USEC":
			fmt.Sscanf(v, "%d", &usec)
		case "MODE":
			mode = v
		}
	}
	if usec == 0 {
		return PowerPending{}
	}
	act := "shutdown"
	if mode == "reboot" || mode == "kexec" {
		act = "restart"
	}
	return PowerPending{Scheduled: true, Action: act, At: time.UnixMicro(usec).UTC().Format(time.RFC3339)}
}
