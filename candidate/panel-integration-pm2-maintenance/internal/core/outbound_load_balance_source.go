package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
)

// Source availability is a third, separately selected scope. A complete,
// successfully committed observation is not proof of healthy business traffic.
func (s *Store) migrateLoadBalanceSourceObservation() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS load_balance_source_observation(
 id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL CHECK(state IN ('ready','unavailable')),
 sequence INTEGER NOT NULL CHECK(sequence>=0 AND sequence<1152921504606846976),checked_at INTEGER NOT NULL CHECK(checked_at>0));
 INSERT OR IGNORE INTO schema_migrations VALUES(46,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) observeLoadBalanceSource(ctx context.Context, ready bool, now int64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if now < 1 {
		return errors.New("告警来源采样时钟不可核对")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT CASE WHEN length(CAST(kinds AS BLOB))<=2048 THEN kinds ELSE NULL END FROM notification_channels WHERE enabled=1 LIMIT 9`)
	if e != nil {
		return e
	}
	subscribed, count := false, 0
	for rows.Next() {
		var raw string
		var kinds []string
		count++
		if rows.Scan(&raw) != nil || count > 8 || json.Unmarshal([]byte(raw), &kinds) != nil || kinds == nil || len(kinds) < 1 || len(kinds) > len(outboundKinds) {
			rows.Close()
			return errors.New("告警来源订阅库存无法完整核对")
		}
		seen := map[string]bool{}
		for _, kind := range kinds {
			if seen[kind] || !containsMenu(outboundKinds, kind) {
				rows.Close()
				return errors.New("告警来源订阅范围不可核对")
			}
			seen[kind] = true
			if kind == "load-balance-source" {
				subscribed = true
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if !subscribed {
		// No implicit source warnings for a Main panel without this application
		// or for old health/traffic-only channels. Existing evidence stays intact.
		return nil
	}
	var previous string
	var sequence, checked int64
	e = tx.QueryRowContext(ctx, `SELECT state,sequence,checked_at FROM load_balance_source_observation WHERE id=1`).Scan(&previous, &sequence, &checked)
	initial := errors.Is(e, sql.ErrNoRows)
	if e != nil && !initial {
		return e
	}
	if !initial && (previous != "ready" && previous != "unavailable" || sequence < 0 || sequence >= 1<<60 || checked < 1 || now < checked) {
		return errors.New("原告警来源状态、序号或时钟不可核对，原证据保留")
	}
	state, source, severity := "unavailable", "app:load-balance-source-unavailable", "critical"
	if ready {
		state, source, severity = "ready", "app:load-balance-source-ready", "info"
	}
	if state != previous && (!initial || !ready) {
		if sequence >= (1<<60)-1 {
			return errors.New("告警来源序号已满，未丢弃原证据")
		}
		var notices int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE kind='load-balance-source'`).Scan(&notices); e != nil {
			return e
		}
		if notices >= 10000 {
			return errors.New("告警来源通知库存已满，原游标保留；未停止实际流量或健康检查")
		}
		sequence++
		_, e = tx.ExecContext(ctx, `INSERT INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'load-balance-source','负载均衡告警来源观察','请核对健康及切流告警源，不代表业务状态',?,?,?,?)`, ID(), severity, source, Hash("load-balance-source:" + strconv.FormatInt(sequence, 10))[:32], now)
		if e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO load_balance_source_observation VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,sequence=excluded.sequence,checked_at=excluded.checked_at`, state, sequence, now)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func outboundEventSource(kind, eventType string) (string, error) {
	if kind == "load-balance-traffic" {
		return loadBalanceTrafficEventSource(eventType)
	}
	if kind == "load-balance-source" {
		switch eventType {
		case "source_unavailable":
			return "app:load-balance-source-unavailable", nil
		case "source_ready":
			return "app:load-balance-source-ready", nil
		}
		return "", errors.New("告警来源事件类型不可核对")
	}
	if eventType != "" {
		return "", errors.New("推送事件类型与范围不匹配")
	}
	return "", nil
}
