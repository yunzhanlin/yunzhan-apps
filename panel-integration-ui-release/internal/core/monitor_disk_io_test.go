package core

import (
	"testing"
	"time"
)

func TestMonitorDiskIORatesAndBootBoundary(t *testing.T) {
	store := testStore(t)
	base := time.Unix(1700000000, 0)
	read, write := uint64(1000), uint64(2000)
	first := monitorFixture(1000, 400, 100, 200, 20, 30, "boot-a")
	first.DiskRead, first.DiskWrite = &read, &write
	result, err := store.RecordMonitorSnapshot(base, first)
	if err != nil || result.DiskReadRate != nil || result.DiskWriteRate != nil {
		t.Fatalf("first rate: %+v %v", result, err)
	}
	read, write = 2500, 5000
	second := monitorFixture(1300, 460, 200, 300, 20, 30, "boot-a")
	second.DiskRead, second.DiskWrite = &read, &write
	result, err = store.RecordMonitorSnapshot(base.Add(15*time.Second), second)
	if err != nil || result.DiskReadRate == nil || *result.DiskReadRate != 100 || result.DiskWriteRate == nil || *result.DiskWriteRate != 200 {
		t.Fatalf("derived rates: %+v %v", result, err)
	}
	points, err := store.MonitorHistory("1h", base.Add(time.Minute))
	if err != nil || len(points) == 0 || points[len(points)-1].DiskReadRate == nil {
		t.Fatalf("history: %+v %v", points, err)
	}
	read, write = 10, 20
	reboot := monitorFixture(100, 40, 10, 20, 20, 30, "boot-b")
	reboot.DiskRead, reboot.DiskWrite = &read, &write
	result, err = store.RecordMonitorSnapshot(base.Add(30*time.Second), reboot)
	if err != nil || result.DiskReadRate != nil || result.DiskWriteRate != nil {
		t.Fatalf("rate crossed reboot: %+v %v", result, err)
	}
	if err = store.migrateMonitorDiskIO(); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
}
