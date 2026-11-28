package main

import (
	"testing"
)

func TestBackupClusterNeedsACluster(t *testing.T) {
	m := &Mgmt{}
	if _, err := m.BackupCluster("t"); err == nil {
		t.Error("ran without a cluster")
	}
}
