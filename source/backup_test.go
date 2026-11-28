package main

import (
	"testing"
	"time"

	"netdir/internal/core"
)

func init() { core.BackupIter = 1000 }

// The schedule of v184-v187 becomes a Scheduler task once, and the old fields are cleared.
func TestBackupScheduleMovesToTheScheduler(t *testing.T) {
	d := core.Settings{Backup: &core.BackupConfig{Enabled: true, At: "03:15", Targets: []core.BackupTarget{{Host: "h", User: "u"}}}}
	core.MigrateBackupSchedule(&d)
	if len(d.Schedule) != 1 || d.Schedule[0].Action != "backup" || d.Schedule[0].Freq != "daily" || d.Backup.Enabled || d.Backup.At != "" {
		t.Fatalf("%+v %+v", d.Schedule, d.Backup)
	}
	if err := core.ValidateSchedule(d.Schedule); err != nil {
		t.Fatal(err)
	}
	if !backupScheduled(d.Schedule, "any") {
		t.Fatal("not scheduled")
	}
	core.MigrateBackupSchedule(&d) // nothing more
	if len(d.Schedule) != 1 {
		t.Fatalf("%+v", d.Schedule)
	}
	// local time becomes UTC
	tk := core.OldBackupTask(0, "03:15", time.FixedZone("x", -7*3600))
	if tk.At != "10:15" || tk.Until != "10:20" {
		t.Fatalf("%+v", tk)
	}
	h := core.OldBackupTask(6, "", time.UTC)
	if h.Freq != "hourly" || h.Every != 6 {
		t.Fatalf("%+v", h)
	}
	if err := core.ValidateSchedule([]core.SchedTask{h}); err != nil {
		t.Fatal(err)
	}
	// switched off: no task, the fields go
	off := core.Settings{Backup: &core.BackupConfig{Hours: 4, Targets: []core.BackupTarget{{Host: "h", User: "u"}}}}
	core.MigrateBackupSchedule(&off)
	if len(off.Schedule) != 0 || off.Backup.Hours != 0 {
		t.Fatalf("%+v", off)
	}
	// a disabled task, or one for other nodes, does not count
	if backupScheduled([]core.SchedTask{{Action: "backup", Disabled: true}}, "n1") || backupScheduled([]core.SchedTask{{Action: "backup", Nodes: []string{"n2"}}}, "n1") {
		t.Fatal("counted")
	}
}
