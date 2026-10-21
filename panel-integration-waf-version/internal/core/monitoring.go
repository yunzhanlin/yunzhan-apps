package core

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"
)

type MonitorSnapshot struct {
	BootID        string  `json:"boot_id"`
	CPUTotal      uint64  `json:"cpu_total"`
	CPUIdle       uint64  `json:"cpu_idle"`
	MemoryTotal   uint64  `json:"memory_total"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	DiskPercent   float64 `json:"disk_percent"`
	DiskRead      *uint64 `json:"disk_read_bytes"`
	DiskWrite     *uint64 `json:"disk_write_bytes"`
	NetworkRX     uint64  `json:"network_rx"`
	NetworkTX     uint64  `json:"network_tx"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Load1         float64 `json:"load_1"`
	SampledAt     string  `json:"sampled_at"`
}

type MonitorSample struct {
	SampledAt     int64    `json:"sampled_at"`
	State         string   `json:"state"`
	Error         string   `json:"error,omitempty"`
	BootID        string   `json:"boot_id,omitempty"`
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryPercent *float64 `json:"memory_percent"`
	DiskPercent   *float64 `json:"disk_percent"`
	DiskReadRate  *float64 `json:"disk_read_rate"`
	DiskWriteRate *float64 `json:"disk_write_rate"`
	RXRate        *float64 `json:"network_rx_rate"`
	TXRate        *float64 `json:"network_tx_rate"`
	MemoryUsed    uint64   `json:"memory_used,omitempty"`
	MemoryTotal   uint64   `json:"memory_total,omitempty"`
	DiskUsed      uint64   `json:"disk_used,omitempty"`
	DiskTotal     uint64   `json:"disk_total,omitempty"`
	UptimeSeconds float64  `json:"uptime_seconds,omitempty"`
	Load1         float64  `json:"load_1,omitempty"`
	CPUTotal      uint64   `json:"-"`
	CPUIdle       uint64   `json:"-"`
	NetworkRX     uint64   `json:"-"`
	NetworkTX     uint64   `json:"-"`
	DiskRead      *uint64  `json:"-"`
	DiskWrite     *uint64  `json:"-"`
}

type MonitorSettings struct {
	RetentionDays   int     `json:"retention_days"`
	CPUThreshold    float64 `json:"cpu_threshold"`
	MemoryThreshold float64 `json:"memory_threshold"`
	DiskThreshold   float64 `json:"disk_threshold"`
	TriggerSeconds  int     `json:"trigger_seconds"`
	RecoverySeconds int     `json:"recovery_seconds"`
	Revision        int64   `json:"revision"`
	UpdatedAt       string  `json:"updated_at"`
}

type MonitorAlert struct {
	ID             string  `json:"id"`
	Metric         string  `json:"metric"`
	State          string  `json:"state"`
	StartedAt      int64   `json:"started_at"`
	LastObservedAt int64   `json:"last_observed_at"`
	ResolvedAt     int64   `json:"resolved_at,omitempty"`
	Peak           float64 `json:"peak"`
	Threshold      float64 `json:"threshold"`
	AcknowledgedAt int64   `json:"acknowledged_at,omitempty"`
}

type MonitorAlertEvent struct {
	ID        int64   `json:"id"`
	AlertID   string  `json:"alert_id"`
	Kind      string  `json:"kind"`
	Value     float64 `json:"value"`
	CreatedAt int64   `json:"created_at"`
}

type MonitorHistoryPoint struct {
	SampledAt     int64    `json:"sampled_at"`
	Samples       int      `json:"samples"`
	Failures      int      `json:"failures"`
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryPercent *float64 `json:"memory_percent"`
	DiskPercent   *float64 `json:"disk_percent"`
	DiskReadRate  *float64 `json:"disk_read_rate"`
	DiskWriteRate *float64 `json:"disk_write_rate"`
	RXRate        *float64 `json:"network_rx_rate"`
	TXRate        *float64 `json:"network_tx_rate"`
	Load1         *float64 `json:"load_1"`
}

type MonitorServiceRequest struct {
	Kind          string `json:"kind"`
	ResourceID    string `json:"resource_id"`
	Label         string `json:"-"`
	ExpectedState string `json:"-"`
}

type MonitorServiceActual struct {
	Kind        string `json:"kind"`
	ResourceID  string `json:"resource_id"`
	ActualState string `json:"actual_state"`
	LoadState   string `json:"load_state"`
	SubState    string `json:"sub_state"`
}

type MonitorServiceStatus struct {
	Kind          string `json:"kind"`
	ResourceID    string `json:"resource_id"`
	Label         string `json:"label"`
	ExpectedState string `json:"expected_state"`
	ActualState   string `json:"actual_state"`
	Detail        string `json:"detail"`
	CheckedAt     int64  `json:"checked_at"`
}

func (s *Store) migrateMonitoring() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS monitor_settings(
 id INTEGER PRIMARY KEY CHECK(id=1),retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 30),
 cpu_threshold REAL NOT NULL CHECK(cpu_threshold BETWEEN 1 AND 100),memory_threshold REAL NOT NULL CHECK(memory_threshold BETWEEN 1 AND 100),disk_threshold REAL NOT NULL CHECK(disk_threshold BETWEEN 1 AND 100),
 trigger_seconds INTEGER NOT NULL CHECK(trigger_seconds BETWEEN 15 AND 3600),recovery_seconds INTEGER NOT NULL CHECK(recovery_seconds BETWEEN 15 AND 3600),revision INTEGER NOT NULL CHECK(revision>0),updated_at TEXT NOT NULL);
 INSERT OR IGNORE INTO monitor_settings VALUES(1,7,80,85,90,300,120,1,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
 CREATE TABLE IF NOT EXISTS monitor_samples(
 id INTEGER PRIMARY KEY AUTOINCREMENT,sampled_at INTEGER NOT NULL UNIQUE,state TEXT NOT NULL CHECK(state IN ('ok','failed')),error TEXT NOT NULL DEFAULT '',boot_id TEXT NOT NULL DEFAULT '',
 cpu_total INTEGER,cpu_idle INTEGER,cpu_percent REAL,memory_used INTEGER,memory_total INTEGER,memory_percent REAL,disk_used INTEGER,disk_total INTEGER,disk_percent REAL,
 network_rx INTEGER,network_tx INTEGER,network_rx_rate REAL,network_tx_rate REAL,uptime_seconds REAL,load_1 REAL);
 CREATE INDEX IF NOT EXISTS monitor_samples_time ON monitor_samples(sampled_at);
 CREATE TABLE IF NOT EXISTS monitor_conditions(metric TEXT PRIMARY KEY,active_since INTEGER NOT NULL DEFAULT 0,clear_since INTEGER NOT NULL DEFAULT 0,last_value REAL NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS monitor_alerts(id TEXT PRIMARY KEY,metric TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','resolved')),started_at INTEGER NOT NULL,last_observed_at INTEGER NOT NULL,resolved_at INTEGER NOT NULL DEFAULT 0,peak REAL NOT NULL,threshold REAL NOT NULL,acknowledged_at INTEGER NOT NULL DEFAULT 0);
 CREATE UNIQUE INDEX IF NOT EXISTS one_active_monitor_alert ON monitor_alerts(metric) WHERE state='active';
 CREATE TABLE IF NOT EXISTS monitor_alert_events(id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT NOT NULL REFERENCES monitor_alerts(id),kind TEXT NOT NULL CHECK(kind IN ('triggered','resolved','acknowledged')),value REAL NOT NULL,created_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS monitor_services(kind TEXT NOT NULL,resource_id TEXT NOT NULL,label TEXT NOT NULL,expected_state TEXT NOT NULL CHECK(expected_state IN ('active','inactive')),actual_state TEXT NOT NULL CHECK(actual_state IN ('active','inactive','failed','unknown')),detail TEXT NOT NULL DEFAULT '',checked_at INTEGER NOT NULL,PRIMARY KEY(kind,resource_id));
 INSERT OR IGNORE INTO schema_migrations VALUES(14,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) ManagedMonitorServices() ([]MonitorServiceRequest, error) {
	out := []MonitorServiceRequest{{Kind: "nginx", ResourceID: "nginx", Label: "Nginx", ExpectedState: "active"}}
	sites, e := s.Sites()
	if e != nil {
		return nil, e
	}
	for _, site := range sites {
		if site.PHPVersionID == "" {
			continue
		}
		id := site.RuntimeInstanceID
		if id == "" {
			id = PHPInstanceID(site)
		}
		expected := "active"
		if site.Status == "stopped" {
			expected = "inactive"
		}
		out = append(out, MonitorServiceRequest{Kind: "php", ResourceID: id, Label: "PHP-FPM · " + site.Name + " · " + strings.TrimPrefix(site.PHPVersionID, "php-"), ExpectedState: expected})
	}
	servers, e := s.DatabaseServers()
	if e != nil {
		return nil, e
	}
	for _, server := range servers {
		expected := "active"
		if server.Status == "stopped" {
			expected = "inactive"
		}
		out = append(out, MonitorServiceRequest{Kind: "mysql", ResourceID: server.ID, Label: "MySQL · " + server.Name + " · " + strings.TrimPrefix(server.ReleaseID, "mysql-"), ExpectedState: expected})
	}
	return out, nil
}

func normalizeServiceState(value string) string {
	switch value {
	case "active", "inactive", "failed":
		return value
	default:
		return "unknown"
	}
}

func serviceMetric(kind, id string) string { return "service:" + kind + ":" + id }

func (s *Store) RecordMonitorServices(at time.Time, expected []MonitorServiceRequest, actual []MonitorServiceActual) error {
	actualByKey := map[string]MonitorServiceActual{}
	for _, item := range actual {
		key := item.Kind + ":" + item.ResourceID
		if item.Kind == "" || item.ResourceID == "" || actualByKey[key].Kind != "" {
			return errors.New("执行器返回的服务状态无效")
		}
		actualByKey[key] = item
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	settings, e := monitoringSettingsTx(tx)
	if e != nil {
		return e
	}
	now := at.Unix()
	current := map[string]bool{}
	for _, item := range expected {
		if item.Kind == "" || item.ResourceID == "" || item.Label == "" || (item.ExpectedState != "active" && item.ExpectedState != "inactive") {
			return errors.New("受管服务清单无效")
		}
		key := item.Kind + ":" + item.ResourceID
		if current[key] {
			return errors.New("受管服务清单重复")
		}
		current[key] = true
		found, ok := actualByKey[key]
		state, detail := "unknown", "未返回状态"
		if ok {
			state = normalizeServiceState(found.ActualState)
			detail = strings.TrimSpace(found.LoadState + " / " + found.SubState)
			if detail == "/" || detail == "" {
				detail = found.ActualState
			}
		}
		if _, e = tx.Exec(`INSERT INTO monitor_services(kind,resource_id,label,expected_state,actual_state,detail,checked_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,resource_id) DO UPDATE SET label=excluded.label,expected_state=excluded.expected_state,actual_state=excluded.actual_state,detail=excluded.detail,checked_at=excluded.checked_at`, item.Kind, item.ResourceID, item.Label, item.ExpectedState, state, detail, now); e != nil {
			return e
		}
		metric := serviceMetric(item.Kind, item.ResourceID)
		if state == "unknown" {
			var active int
			_ = tx.QueryRow(`SELECT COUNT(*) FROM monitor_alerts WHERE metric=? AND state='active'`, metric).Scan(&active)
			if active == 0 {
				_, e = tx.Exec(`UPDATE monitor_conditions SET active_since=0,clear_since=0 WHERE metric=?`, metric)
			}
		} else {
			value := float64(0)
			if state != item.ExpectedState {
				value = 1
			}
			e = evaluateMonitorMetric(tx, now, metric, value, 1, int64(settings.TriggerSeconds), int64(settings.RecoverySeconds))
		}
		if e != nil {
			return e
		}
	}
	rows, e := tx.Query(`SELECT kind,resource_id FROM monitor_services`)
	if e != nil {
		return e
	}
	var removed [][2]string
	for rows.Next() {
		var kind, id string
		if e = rows.Scan(&kind, &id); e != nil {
			rows.Close()
			return e
		}
		if !current[kind+":"+id] {
			removed = append(removed, [2]string{kind, id})
		}
	}
	rows.Close()
	for _, item := range removed {
		metric := serviceMetric(item[0], item[1])
		var alertID string
		if e = tx.QueryRow(`SELECT id FROM monitor_alerts WHERE metric=? AND state='active'`, metric).Scan(&alertID); e == nil {
			if _, e = tx.Exec(`UPDATE monitor_alerts SET state='resolved',last_observed_at=?,resolved_at=? WHERE id=?`, now, now, alertID); e == nil {
				_, e = tx.Exec(`INSERT INTO monitor_alert_events(alert_id,kind,value,created_at) VALUES(?,'resolved',0,?)`, alertID, now)
			}
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.Exec(`DELETE FROM monitor_conditions WHERE metric=?`, metric); e != nil {
			return e
		}
		if _, e = tx.Exec(`DELETE FROM monitor_services WHERE kind=? AND resource_id=?`, item[0], item[1]); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func (s *Store) MonitorServices() ([]MonitorServiceStatus, error) {
	rows, e := s.DB.Query(`SELECT kind,resource_id,label,expected_state,actual_state,detail,checked_at FROM monitor_services ORDER BY CASE kind WHEN 'nginx' THEN 0 WHEN 'php' THEN 1 ELSE 2 END,label,resource_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []MonitorServiceStatus{}
	for rows.Next() {
		var item MonitorServiceStatus
		if e = rows.Scan(&item.Kind, &item.ResourceID, &item.Label, &item.ExpectedState, &item.ActualState, &item.Detail, &item.CheckedAt); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) MonitoringSettings() (MonitorSettings, error) {
	var v MonitorSettings
	e := s.DB.QueryRow(`SELECT retention_days,cpu_threshold,memory_threshold,disk_threshold,trigger_seconds,recovery_seconds,revision,updated_at FROM monitor_settings WHERE id=1`).Scan(&v.RetentionDays, &v.CPUThreshold, &v.MemoryThreshold, &v.DiskThreshold, &v.TriggerSeconds, &v.RecoverySeconds, &v.Revision, &v.UpdatedAt)
	return v, e
}

func validMonitorSettings(v MonitorSettings) bool {
	return v.RetentionDays >= 1 && v.RetentionDays <= 30 && v.CPUThreshold >= 1 && v.CPUThreshold <= 100 && v.MemoryThreshold >= 1 && v.MemoryThreshold <= 100 && v.DiskThreshold >= 1 && v.DiskThreshold <= 100 && v.TriggerSeconds >= 15 && v.TriggerSeconds <= 3600 && v.RecoverySeconds >= 15 && v.RecoverySeconds <= 3600 && v.Revision > 0
}

func (s *Store) UpdateMonitoringSettings(v MonitorSettings, actor string) (MonitorSettings, error) {
	if !validMonitorSettings(v) {
		return v, errors.New("监控设置超出允许范围")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	result, e := tx.Exec(`UPDATE monitor_settings SET retention_days=?,cpu_threshold=?,memory_threshold=?,disk_threshold=?,trigger_seconds=?,recovery_seconds=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?`, v.RetentionDays, v.CPUThreshold, v.MemoryThreshold, v.DiskThreshold, v.TriggerSeconds, v.RecoverySeconds, Now(), v.Revision)
	if e != nil {
		return v, e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return v, errors.New("监控设置已变化，请刷新后重试")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'monitor.settings','monitor','success',?)`, actor, Now()); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	return s.MonitoringSettings()
}

func nullable(v float64) *float64 { x := v; return &x }
func counterValue(v *uint64) any {
	if v == nil {
		return nil
	}
	return int64(*v)
}

func (s *Store) RecordMonitorSnapshot(at time.Time, v MonitorSnapshot) (MonitorSample, error) {
	if v.BootID == "" || v.CPUTotal == 0 || v.CPUIdle > v.CPUTotal || v.MemoryTotal == 0 || v.MemoryUsed > v.MemoryTotal || v.DiskTotal == 0 || v.DiskUsed > v.DiskTotal || math.IsNaN(v.MemoryPercent) || math.IsNaN(v.DiskPercent) {
		return MonitorSample{}, errors.New("执行器返回的监控样本无效")
	}
	now := at.Unix()
	out := MonitorSample{SampledAt: now, State: "ok", BootID: v.BootID, MemoryPercent: nullable(v.MemoryPercent), DiskPercent: nullable(v.DiskPercent), MemoryUsed: v.MemoryUsed, MemoryTotal: v.MemoryTotal, DiskUsed: v.DiskUsed, DiskTotal: v.DiskTotal, UptimeSeconds: v.UptimeSeconds, Load1: v.Load1, CPUTotal: v.CPUTotal, CPUIdle: v.CPUIdle, NetworkRX: v.NetworkRX, NetworkTX: v.NetworkTX, DiskRead: v.DiskRead, DiskWrite: v.DiskWrite}
	var previous MonitorSample
	var cpuTotal, cpuIdle, rx, tx, diskRead, diskWrite sql.NullInt64
	var boot string
	e := s.DB.QueryRow(`SELECT sampled_at,boot_id,cpu_total,cpu_idle,network_rx,network_tx,disk_read,disk_write FROM monitor_samples WHERE state='ok' ORDER BY sampled_at DESC LIMIT 1`).Scan(&previous.SampledAt, &boot, &cpuTotal, &cpuIdle, &rx, &tx, &diskRead, &diskWrite)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e == nil && boot == v.BootID && now > previous.SampledAt && now-previous.SampledAt <= 120 && cpuTotal.Valid && cpuIdle.Valid && rx.Valid && tx.Valid {
		if v.CPUTotal >= uint64(cpuTotal.Int64) && v.CPUIdle >= uint64(cpuIdle.Int64) {
			dTotal := v.CPUTotal - uint64(cpuTotal.Int64)
			dIdle := v.CPUIdle - uint64(cpuIdle.Int64)
			if dTotal > 0 && dIdle <= dTotal {
				out.CPUPercent = nullable(float64(dTotal-dIdle) * 100 / float64(dTotal))
			}
		}
		seconds := float64(now - previous.SampledAt)
		if v.NetworkRX >= uint64(rx.Int64) {
			out.RXRate = nullable(float64(v.NetworkRX-uint64(rx.Int64)) / seconds)
		}
		if v.NetworkTX >= uint64(tx.Int64) {
			out.TXRate = nullable(float64(v.NetworkTX-uint64(tx.Int64)) / seconds)
		}
		if v.DiskRead != nil && diskRead.Valid && *v.DiskRead >= uint64(diskRead.Int64) {
			out.DiskReadRate = nullable(float64(*v.DiskRead-uint64(diskRead.Int64)) / seconds)
		}
		if v.DiskWrite != nil && diskWrite.Valid && *v.DiskWrite >= uint64(diskWrite.Int64) {
			out.DiskWriteRate = nullable(float64(*v.DiskWrite-uint64(diskWrite.Int64)) / seconds)
		}
	}
	txDB, e := s.DB.Begin()
	if e != nil {
		return out, e
	}
	defer txDB.Rollback()
	_, e = txDB.Exec(`INSERT INTO monitor_samples(sampled_at,state,boot_id,cpu_total,cpu_idle,cpu_percent,memory_used,memory_total,memory_percent,disk_used,disk_total,disk_percent,network_rx,network_tx,network_rx_rate,network_tx_rate,uptime_seconds,load_1,disk_read,disk_write,disk_read_rate,disk_write_rate) VALUES(?,'ok',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, now, v.BootID, v.CPUTotal, v.CPUIdle, out.CPUPercent, v.MemoryUsed, v.MemoryTotal, v.MemoryPercent, v.DiskUsed, v.DiskTotal, v.DiskPercent, v.NetworkRX, v.NetworkTX, out.RXRate, out.TXRate, v.UptimeSeconds, v.Load1, counterValue(v.DiskRead), counterValue(v.DiskWrite), out.DiskReadRate, out.DiskWriteRate)
	if e != nil {
		return out, e
	}
	settings, e := monitoringSettingsTx(txDB)
	if e == nil {
		e = evaluateMonitorAlerts(txDB, now, settings, out)
	}
	if e == nil {
		e = evaluateMonitorMetric(txDB, now, "collector", 0, 1, int64(settings.TriggerSeconds), int64(settings.RecoverySeconds))
	}
	if e != nil {
		return out, e
	}
	return out, txDB.Commit()
}

func (s *Store) RecordMonitorFailure(at time.Time, message string) error {
	if len(message) > 500 {
		message = message[:500]
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO monitor_samples(sampled_at,state,error) VALUES(?,'failed',?) ON CONFLICT(sampled_at) DO NOTHING`, at.Unix(), message); e != nil {
		return e
	}
	// Missing data is not zero or recovery. It only breaks an untriggered streak.
	if _, e = tx.Exec(`UPDATE monitor_conditions SET active_since=0,clear_since=0 WHERE metric!='collector' AND metric NOT IN (SELECT metric FROM monitor_alerts WHERE state='active')`); e != nil {
		return e
	}
	settings, e := monitoringSettingsTx(tx)
	if e == nil {
		e = evaluateMonitorMetric(tx, at.Unix(), "collector", 1, 1, int64(settings.TriggerSeconds), int64(settings.RecoverySeconds))
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}

func monitoringSettingsTx(tx *sql.Tx) (MonitorSettings, error) {
	var v MonitorSettings
	e := tx.QueryRow(`SELECT retention_days,cpu_threshold,memory_threshold,disk_threshold,trigger_seconds,recovery_seconds,revision,updated_at FROM monitor_settings WHERE id=1`).Scan(&v.RetentionDays, &v.CPUThreshold, &v.MemoryThreshold, &v.DiskThreshold, &v.TriggerSeconds, &v.RecoverySeconds, &v.Revision, &v.UpdatedAt)
	return v, e
}

func evaluateMonitorAlerts(tx *sql.Tx, now int64, settings MonitorSettings, sample MonitorSample) error {
	metrics := []struct {
		name      string
		value     *float64
		threshold float64
	}{{"cpu", sample.CPUPercent, settings.CPUThreshold}, {"memory", sample.MemoryPercent, settings.MemoryThreshold}, {"disk", sample.DiskPercent, settings.DiskThreshold}}
	for _, metric := range metrics {
		if metric.value == nil {
			continue
		}
		if e := evaluateMonitorMetric(tx, now, metric.name, *metric.value, metric.threshold, int64(settings.TriggerSeconds), int64(settings.RecoverySeconds)); e != nil {
			return e
		}
	}
	return nil
}

func evaluateMonitorMetric(tx *sql.Tx, now int64, metric string, value, threshold float64, trigger, recovery int64) error {
	var activeSince, clearSince int64
	_ = tx.QueryRow(`SELECT active_since,clear_since FROM monitor_conditions WHERE metric=?`, metric).Scan(&activeSince, &clearSince)
	var alert MonitorAlert
	e := tx.QueryRow(`SELECT id,metric,state,started_at,last_observed_at,resolved_at,peak,threshold,acknowledged_at FROM monitor_alerts WHERE metric=? AND state='active'`, metric).Scan(&alert.ID, &alert.Metric, &alert.State, &alert.StartedAt, &alert.LastObservedAt, &alert.ResolvedAt, &alert.Peak, &alert.Threshold, &alert.AcknowledgedAt)
	hasAlert := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if errors.Is(e, sql.ErrNoRows) {
		e = nil
	}
	if value >= threshold {
		clearSince = 0
		if hasAlert {
			peak := math.Max(alert.Peak, value)
			_, e = tx.Exec(`UPDATE monitor_alerts SET last_observed_at=?,peak=? WHERE id=?`, now, peak, alert.ID)
		} else {
			if activeSince == 0 {
				activeSince = now
			}
			if now-activeSince >= trigger {
				id := ID()
				_, e = tx.Exec(`INSERT INTO monitor_alerts(id,metric,state,started_at,last_observed_at,peak,threshold) VALUES(?,?,'active',?,?,?,?)`, id, metric, activeSince, now, value, threshold)
				if e == nil {
					_, e = tx.Exec(`INSERT INTO monitor_alert_events(alert_id,kind,value,created_at) VALUES(?,'triggered',?,?)`, id, value, now)
				}
			}
		}
	} else if hasAlert {
		activeSince = 0
		if value <= math.Max(0, threshold-5) {
			if clearSince == 0 {
				clearSince = now
			}
			if now-clearSince >= recovery {
				_, e = tx.Exec(`UPDATE monitor_alerts SET state='resolved',last_observed_at=?,resolved_at=? WHERE id=?`, now, now, alert.ID)
				if e == nil {
					_, e = tx.Exec(`INSERT INTO monitor_alert_events(alert_id,kind,value,created_at) VALUES(?,'resolved',?,?)`, alert.ID, value, now)
				}
				clearSince = 0
			}
		} else {
			clearSince = 0
		}
	} else {
		activeSince = 0
		clearSince = 0
	}
	if e != nil {
		return e
	}
	_, e = tx.Exec(`INSERT INTO monitor_conditions(metric,active_since,clear_since,last_value) VALUES(?,?,?,?) ON CONFLICT(metric) DO UPDATE SET active_since=excluded.active_since,clear_since=excluded.clear_since,last_value=excluded.last_value`, metric, activeSince, clearSince, value)
	return e
}

func (s *Store) CleanupMonitoring(now time.Time) error {
	settings, e := s.MonitoringSettings()
	if e != nil {
		return e
	}
	cutoff := now.Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour).Unix()
	maxSamples := settings.RetentionDays*24*60*4 + 4
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, statement := range []struct {
		query string
		arg   int64
	}{
		{`DELETE FROM monitor_samples WHERE sampled_at<?`, cutoff},
		{`DELETE FROM monitor_samples WHERE id IN (SELECT id FROM monitor_samples ORDER BY sampled_at DESC,id DESC LIMIT -1 OFFSET ?)`, int64(maxSamples)},
		{`DELETE FROM monitor_alert_events WHERE created_at<? AND alert_id IN (SELECT id FROM monitor_alerts WHERE state='resolved')`, cutoff},
		{`DELETE FROM monitor_alerts WHERE state='resolved' AND resolved_at<?`, cutoff},
	} {
		if _, e = tx.Exec(statement.query, statement.arg); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func monitorRange(value string) (int64, int64, bool) {
	ranges := map[string]int64{"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
	seconds, ok := ranges[value]
	if !ok {
		return 0, 0, false
	}
	bucket := int64(math.Ceil(float64(seconds) / 480))
	if bucket < 15 {
		bucket = 15
	}
	return seconds, bucket, true
}

func (s *Store) MonitorHistory(value string, now time.Time) ([]MonitorHistoryPoint, error) {
	seconds, bucket, ok := monitorRange(value)
	if !ok {
		return nil, errors.New("监控时间范围无效")
	}
	rows, e := s.DB.Query(`SELECT (sampled_at/?)*?,COUNT(*),SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END),AVG(cpu_percent),AVG(memory_percent),AVG(disk_percent),AVG(network_rx_rate),AVG(network_tx_rate),AVG(load_1),AVG(disk_read_rate),AVG(disk_write_rate) FROM monitor_samples WHERE sampled_at>=? GROUP BY 1 ORDER BY 1`, bucket, bucket, now.Unix()-seconds)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []MonitorHistoryPoint{}
	for rows.Next() {
		var p MonitorHistoryPoint
		var cpu, memory, disk, rx, tx, load, diskRead, diskWrite sql.NullFloat64
		if e = rows.Scan(&p.SampledAt, &p.Samples, &p.Failures, &cpu, &memory, &disk, &rx, &tx, &load, &diskRead, &diskWrite); e != nil {
			return nil, e
		}
		if cpu.Valid {
			p.CPUPercent = nullable(cpu.Float64)
		}
		if memory.Valid {
			p.MemoryPercent = nullable(memory.Float64)
		}
		if disk.Valid {
			p.DiskPercent = nullable(disk.Float64)
		}
		if diskRead.Valid {
			p.DiskReadRate = nullable(diskRead.Float64)
		}
		if diskWrite.Valid {
			p.DiskWriteRate = nullable(diskWrite.Float64)
		}
		if rx.Valid {
			p.RXRate = nullable(rx.Float64)
		}
		if tx.Valid {
			p.TXRate = nullable(tx.Float64)
		}
		if load.Valid {
			p.Load1 = nullable(load.Float64)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) MonitorAlerts() ([]MonitorAlert, []MonitorAlertEvent, error) {
	rows, e := s.DB.Query(`SELECT id,metric,state,started_at,last_observed_at,resolved_at,peak,threshold,acknowledged_at FROM monitor_alerts ORDER BY CASE state WHEN 'active' THEN 0 ELSE 1 END,started_at DESC LIMIT 200`)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	alerts := []MonitorAlert{}
	for rows.Next() {
		var a MonitorAlert
		if e = rows.Scan(&a.ID, &a.Metric, &a.State, &a.StartedAt, &a.LastObservedAt, &a.ResolvedAt, &a.Peak, &a.Threshold, &a.AcknowledgedAt); e != nil {
			return nil, nil, e
		}
		alerts = append(alerts, a)
	}
	events, e := s.DB.Query(`SELECT id,alert_id,kind,value,created_at FROM monitor_alert_events ORDER BY id DESC LIMIT 300`)
	if e != nil {
		return nil, nil, e
	}
	defer events.Close()
	history := []MonitorAlertEvent{}
	for events.Next() {
		var v MonitorAlertEvent
		if e = events.Scan(&v.ID, &v.AlertID, &v.Kind, &v.Value, &v.CreatedAt); e != nil {
			return nil, nil, e
		}
		history = append(history, v)
	}
	return alerts, history, events.Err()
}

func (s *Store) AcknowledgeMonitorAlert(id string, now time.Time, actor string) error {
	if !ValidID(id) {
		return errors.New("告警标识无效")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var value float64
	var acknowledged int64
	if e = tx.QueryRow(`SELECT peak,acknowledged_at FROM monitor_alerts WHERE id=?`, id).Scan(&value, &acknowledged); e != nil {
		return errors.New("告警不存在")
	}
	if acknowledged == 0 {
		if _, e = tx.Exec(`UPDATE monitor_alerts SET acknowledged_at=? WHERE id=?`, now.Unix(), id); e != nil {
			return e
		}
		if _, e = tx.Exec(`INSERT INTO monitor_alert_events(alert_id,kind,value,created_at) VALUES(?,'acknowledged',?,?)`, id, value, now.Unix()); e != nil {
			return e
		}
		if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'monitor.acknowledge',?,'success',?)`, actor, id, Now()); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func RunMonitoringWorker(ctx context.Context, s *Store, ex *ExecutorClient) {
	collect := func() {
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var v MonitorSnapshot
		e := ex.Call(callCtx, "GET", "/v1/overview", nil, &v)
		now := time.Now()
		if e != nil {
			_ = s.RecordMonitorFailure(now, e.Error())
		} else if _, e = s.RecordMonitorSnapshot(now, v); e != nil {
			_ = s.RecordMonitorFailure(now, e.Error())
		}
		expected, serviceErr := s.ManagedMonitorServices()
		if serviceErr != nil {
			return
		}
		var response struct {
			Services []MonitorServiceActual `json:"services"`
		}
		serviceErr = ex.Call(callCtx, "POST", "/v1/monitor/services", map[string]any{"services": expected}, &response)
		if serviceErr != nil {
			response.Services = make([]MonitorServiceActual, 0, len(expected))
			for _, item := range expected {
				response.Services = append(response.Services, MonitorServiceActual{Kind: item.Kind, ResourceID: item.ResourceID, ActualState: "unknown", LoadState: "check failed"})
			}
		}
		_ = s.RecordMonitorServices(now, expected, response.Services)
	}
	ticker := time.NewTicker(15 * time.Second)
	cleanup := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer cleanup.Stop()
	collect()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		case now := <-cleanup.C:
			_ = s.CleanupMonitoring(now)
		}
	}
}
