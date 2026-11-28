package main

import (
	"netdir/internal/core"
)

// backupScheduled says whether an enabled backup task runs on the node.
func backupScheduled(tasks []core.SchedTask, node string) bool {
	for i := range tasks {
		if t := &tasks[i]; t.Action == "backup" && !t.Disabled && t.AppliesTo(node) {
			return true
		}
	}
	return false
}
