package core

import (
	"math"
	"testing"
	"time"
)

func monitorFixture(cpuTotal, cpuIdle, rx, tx uint64, memory, disk float64, boot string) MonitorSnapshot {
	return MonitorSnapshot{BootID: boot, CPUTotal: cpuTotal, CPUIdle: cpuIdle, MemoryTotal: 1000, MemoryUsed: uint64(memory * 10), MemoryPercent: memory, DiskTotal: 2000, DiskUsed: uint64(disk * 20), DiskPercent: disk, NetworkRX: rx, NetworkTX: tx, UptimeSeconds: 100, Load1: 0.5}
}

func TestMonitoringRatesResetAndHistory(t *testing.T) {
	s := testStore(t)
	base := time.Unix(1700000000, 0)
	first, e := s.RecordMonitorSnapshot(base, monitorFixture(1000, 400, 10000, 20000, 40, 50, "boot-a"))
	if e != nil {
		t.Fatal(e)
	}
	if first.CPUPercent != nil || first.RXRate != nil || first.TXRate != nil {
		t.Fatal("first sample fabricated rates")
	}
	second, e := s.RecordMonitorSnapshot(base.Add(15*time.Second), monitorFixture(1300, 460, 11500, 23000, 41, 51, "boot-a"))
	if e != nil {
		t.Fatal(e)
	}
	if second.CPUPercent == nil || math.Abs(*second.CPUPercent-80) > 0.001 || second.RXRate == nil || *second.RXRate != 100 || second.TXRate == nil || *second.TXRate != 200 {
		t.Fatal("wrong derived rates", second)
	}
	reboot, e := s.RecordMonitorSnapshot(base.Add(30*time.Second), monitorFixture(20, 8, 20, 30, 42, 52, "boot-b"))
	if e != nil {
		t.Fatal(e)
	}
	if reboot.CPUPercent != nil || reboot.RXRate != nil {
		t.Fatal("rates crossed boot boundary")
	}
	reset, e := s.RecordMonitorSnapshot(base.Add(45*time.Second), monitorFixture(40, 10, 10, 40, 43, 53, "boot-b"))
	if e != nil {
		t.Fatal(e)
	}
	if reset.RXRate != nil || reset.TXRate == nil {
		t.Fatal("counter reset not isolated per direction")
	}
	if e = s.RecordMonitorFailure(base.Add(60*time.Second), "executor unavailable"); e != nil {
		t.Fatal(e)
	}
	points, e := s.MonitorHistory("1h", base.Add(time.Hour))
	if e != nil || len(points) == 0 {
		t.Fatal("history missing", e)
	}
	failures := 0
	for _, p := range points {
		failures += p.Failures
	}
	if failures != 1 {
		t.Fatal("failure gap not visible", failures)
	}
	if _, e = s.MonitorHistory("year", base); e == nil {
		t.Fatal("unbounded history range accepted")
	}
}

func TestMonitoringAlertDurationRecoveryAndAcknowledgement(t *testing.T) {
	s := testStore(t)
	settings, _ := s.MonitoringSettings()
	settings.CPUThreshold = 70
	settings.MemoryThreshold = 90
	settings.DiskThreshold = 95
	settings.TriggerSeconds = 15
	settings.RecoverySeconds = 15
	settings, e := s.UpdateMonitoringSettings(settings, "admin")
	if e != nil {
		t.Fatal(e)
	}
	base := time.Unix(1700100000, 0)
	if _, e = s.RecordMonitorSnapshot(base, monitorFixture(1000, 500, 100, 100, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordMonitorSnapshot(base.Add(15*time.Second), monitorFixture(1200, 520, 200, 200, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	alerts, events, e := s.MonitorAlerts()
	if e != nil {
		t.Fatal(e)
	}
	if len(alerts) != 0 || len(events) != 0 {
		t.Fatal("alert triggered without full duration")
	}
	if _, e = s.RecordMonitorSnapshot(base.Add(30*time.Second), monitorFixture(1400, 540, 300, 300, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	alerts, events, e = s.MonitorAlerts()
	if e != nil || len(alerts) != 1 || alerts[0].State != "active" || len(events) != 1 || events[0].Kind != "triggered" {
		t.Fatal("alert did not trigger", alerts, events, e)
	}
	id := alerts[0].ID
	if e = s.AcknowledgeMonitorAlert(id, base.Add(31*time.Second), "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.AcknowledgeMonitorAlert(id, base.Add(32*time.Second), "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordMonitorSnapshot(base.Add(45*time.Second), monitorFixture(1600, 680, 400, 400, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordMonitorSnapshot(base.Add(60*time.Second), monitorFixture(1800, 820, 500, 500, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	alerts, events, e = s.MonitorAlerts()
	if e != nil || alerts[0].State != "resolved" {
		t.Fatal("alert did not resolve", alerts, e)
	}
	triggered, resolved, ack := 0, 0, 0
	for _, v := range events {
		switch v.Kind {
		case "triggered":
			triggered++
		case "resolved":
			resolved++
		case "acknowledged":
			ack++
		}
	}
	if triggered != 1 || resolved != 1 || ack != 1 {
		t.Fatal("event duplication", triggered, resolved, ack)
	}
	var audits int
	s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='monitor.acknowledge' AND target=?`, id).Scan(&audits)
	if audits != 1 {
		t.Fatal("duplicate acknowledgement audit")
	}
	settings.Revision--
	if _, e = s.UpdateMonitoringSettings(settings, "admin"); e == nil {
		t.Fatal("stale settings accepted")
	}
}

func TestMonitoringRetentionAndInvalidSnapshot(t *testing.T) {
	s := testStore(t)
	base := time.Unix(1700200000, 0)
	if _, e := s.RecordMonitorSnapshot(base, MonitorSnapshot{}); e == nil {
		t.Fatal("invalid sample accepted")
	}
	if e := s.RecordMonitorFailure(base, "down"); e != nil {
		t.Fatal(e)
	}
	settings, _ := s.MonitoringSettings()
	settings.RetentionDays = 1
	if _, e := s.UpdateMonitoringSettings(settings, "admin"); e != nil {
		t.Fatal(e)
	}
	if e := s.CleanupMonitoring(base.Add(25 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM monitor_samples`).Scan(&count)
	if count != 0 {
		t.Fatal("expired sample retained")
	}
	settings, _ = s.MonitoringSettings()
	settings.RetentionDays = 1
	if _, e := s.UpdateMonitoringSettings(settings, "admin"); e != nil {
		t.Fatal(e)
	}
	limit := 24*60*4 + 4
	for n := 0; n < limit+20; n++ {
		if _, e := s.DB.Exec(`INSERT INTO monitor_samples(sampled_at,state,error) VALUES(?,'failed','bounded')`, base.Add(time.Duration(n)*time.Second).Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.CleanupMonitoring(base.Add(time.Duration(limit+20) * time.Second)); e != nil {
		t.Fatal(e)
	}
	s.DB.QueryRow(`SELECT count(*) FROM monitor_samples`).Scan(&count)
	if count != limit {
		t.Fatal("sample cap not enforced", count, limit)
	}
}

func TestMonitoringManagedServiceStateAndUnknownGap(t *testing.T) {
	s := testStore(t)
	settings, _ := s.MonitoringSettings()
	settings.TriggerSeconds = 15
	settings.RecoverySeconds = 15
	if _, e := s.UpdateMonitoringSettings(settings, "admin"); e != nil {
		t.Fatal(e)
	}
	base := time.Unix(1700300000, 0)
	expected := []MonitorServiceRequest{
		{Kind: "nginx", ResourceID: "nginx", Label: "Nginx", ExpectedState: "active"},
		{Kind: "mysql", ResourceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Label: "MySQL test", ExpectedState: "inactive"},
	}
	mismatch := []MonitorServiceActual{
		{Kind: "nginx", ResourceID: "nginx", ActualState: "inactive", LoadState: "loaded", SubState: "dead"},
		{Kind: "mysql", ResourceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ActualState: "inactive", LoadState: "loaded", SubState: "dead"},
	}
	if e := s.RecordMonitorServices(base, expected, mismatch); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordMonitorServices(base.Add(15*time.Second), expected, mismatch); e != nil {
		t.Fatal(e)
	}
	alerts, events, e := s.MonitorAlerts()
	if e != nil || len(alerts) != 1 || alerts[0].Metric != "service:nginx:nginx" || alerts[0].State != "active" || len(events) != 1 {
		t.Fatal("service mismatch alert missing or stopped service misreported", alerts, events, e)
	}
	unknown := []MonitorServiceActual{{Kind: "nginx", ResourceID: "nginx", ActualState: "unknown"}}
	if e = s.RecordMonitorServices(base.Add(30*time.Second), expected, unknown); e != nil {
		t.Fatal(e)
	}
	alerts, _, _ = s.MonitorAlerts()
	if alerts[0].State != "active" {
		t.Fatal("unknown state falsely recovered alert")
	}
	healthy := []MonitorServiceActual{
		{Kind: "nginx", ResourceID: "nginx", ActualState: "active", LoadState: "loaded", SubState: "running"},
		{Kind: "mysql", ResourceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ActualState: "inactive", LoadState: "loaded", SubState: "dead"},
	}
	if e = s.RecordMonitorServices(base.Add(45*time.Second), expected, healthy); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordMonitorServices(base.Add(60*time.Second), expected, healthy); e != nil {
		t.Fatal(e)
	}
	alerts, events, _ = s.MonitorAlerts()
	if alerts[0].State != "resolved" || len(events) != 2 || events[0].Kind != "resolved" {
		t.Fatal("service alert did not recover once state matched", alerts, events)
	}
	services, e := s.MonitorServices()
	if e != nil || len(services) != 2 || services[0].ActualState != "active" || services[1].ExpectedState != "inactive" {
		t.Fatal("service current state missing", services, e)
	}
}

func TestMonitoringRemovesReplacedServiceInstance(t *testing.T) {
	s := testStore(t)
	settings, _ := s.MonitoringSettings()
	settings.TriggerSeconds = 15
	settings.RecoverySeconds = 15
	if _, e := s.UpdateMonitoringSettings(settings, "admin"); e != nil {
		t.Fatal(e)
	}
	base := time.Unix(1700300000, 0)
	old := MonitorServiceRequest{Kind: "php", ResourceID: "site-php-old", Label: "PHP old", ExpectedState: "active"}
	newInstance := MonitorServiceRequest{Kind: "php", ResourceID: "site-php-new", Label: "PHP new", ExpectedState: "active"}
	if e := s.RecordMonitorServices(base, []MonitorServiceRequest{old}, []MonitorServiceActual{{Kind: old.Kind, ResourceID: old.ResourceID, ActualState: "inactive"}}); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordMonitorServices(base.Add(15*time.Second), []MonitorServiceRequest{old}, []MonitorServiceActual{{Kind: old.Kind, ResourceID: old.ResourceID, ActualState: "inactive"}}); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordMonitorServices(base.Add(time.Minute), []MonitorServiceRequest{newInstance}, []MonitorServiceActual{{Kind: newInstance.Kind, ResourceID: newInstance.ResourceID, ActualState: "active"}}); e != nil {
		t.Fatal(e)
	}
	services, e := s.MonitorServices()
	if e != nil || len(services) != 1 || services[0].ResourceID != newInstance.ResourceID {
		t.Fatalf("replaced PHP service remains in current monitor state: %+v, %v", services, e)
	}
	alerts, events, e := s.MonitorAlerts()
	if e != nil || len(alerts) != 1 || alerts[0].State != "resolved" || len(events) != 2 || events[0].Kind != "resolved" {
		t.Fatalf("replaced service alert was not resolved: %+v, %+v, %v", alerts, events, e)
	}
}

func TestMonitoringCollectorFailureTriggersAndRecovers(t *testing.T) {
	s := testStore(t)
	settings, _ := s.MonitoringSettings()
	settings.TriggerSeconds = 15
	settings.RecoverySeconds = 15
	if _, e := s.UpdateMonitoringSettings(settings, "admin"); e != nil {
		t.Fatal(e)
	}
	base := time.Unix(1700400000, 0)
	if e := s.RecordMonitorFailure(base, "executor down"); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordMonitorFailure(base.Add(15*time.Second), "executor down"); e != nil {
		t.Fatal(e)
	}
	alerts, _, _ := s.MonitorAlerts()
	if len(alerts) != 1 || alerts[0].Metric != "collector" || alerts[0].State != "active" {
		t.Fatal("collector alert missing", alerts)
	}
	if _, e := s.RecordMonitorSnapshot(base.Add(30*time.Second), monitorFixture(100, 50, 10, 10, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.RecordMonitorSnapshot(base.Add(45*time.Second), monitorFixture(200, 100, 20, 20, 20, 20, "boot")); e != nil {
		t.Fatal(e)
	}
	alerts, events, _ := s.MonitorAlerts()
	if alerts[0].State != "resolved" || len(events) != 2 || events[0].Kind != "resolved" {
		t.Fatal("collector alert did not recover", alerts, events)
	}
}
