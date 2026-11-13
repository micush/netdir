package main

import (
	"path/filepath"

	"netdir/device"
)

// startContentLog sets where the per-device content logs go (<state dir>/content/<device>.log).  Nothing is written for a device
// unless its options say content_log=on; see device/contentlog.go for the options and what is and is not logged.
func startContentLog(stateDir string) {
	device.ContentLogDir = filepath.Join(stateDir, "content")
}
