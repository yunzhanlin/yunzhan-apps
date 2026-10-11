package core

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// This is a separate opt-in scope: a health-only subscription must not acquire
// new traffic/worker messages. No domains, nodes, configuration or errors cross
// this closed executor contract.
type LoadBalanceTrafficRecord struct {
	ID        string `json:"id"`
	EntryID   string `json:"entry_id"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}
type LoadBalanceTrafficFeed struct {
	SchemaVersion   int                        `json:"schema_version"`
	Available       bool                       `json:"available"`
	Records         []LoadBalanceTrafficRecord `json:"records"`
	WorkerState     string                     `json:"worker_state"`
	WorkerCheckedAt string                     `json:"worker_checked_at"`
}

func loadBalanceTrafficEventType(source string) string {
	switch source {
	case "app:load-balance-traffic-committed":
		return "traffic_committed"
	case "app:load-balance-traffic-recovered":
		return "traffic_recovered"
	case "app:load-balance-traffic-pending":
		return "traffic_pending"
	case "app:load-balance-worker":
		return "worker_observation"
	}
	return ""
}
func loadBalanceTrafficEventSource(kind string) (string, error) {
	switch kind {
	case "":
		return "", nil
	case "traffic_committed":
		return "app:load-balance-traffic-committed", nil
	case "traffic_recovered":
		return "app:load-balance-traffic-recovered", nil
	case "traffic_pending":
		return "app:load-balance-traffic-pending", nil
	case "worker_observation":
		return "app:load-balance-worker", nil
	}
	return "", errors.New("切流推送事件类型不可核对")
}

func ValidateLoadBalanceTrafficFeed(f LoadBalanceTrafficFeed, now time.Time) error {
	if f.SchemaVersion != 1 || f.Records == nil || len(f.Records) > 2560 || (!f.Available && (len(f.Records) > 0 || f.WorkerState != "unknown" || f.WorkerCheckedAt != "")) {
		return errors.New("切流告警源完整库存不可核对")
	}
	if f.WorkerState != "unknown" && f.WorkerState != "clear" && f.WorkerState != "error" && f.WorkerState != "stale" {
		return errors.New("切流调度状态不可核对")
	}
	if f.WorkerState == "unknown" {
		if f.WorkerCheckedAt != "" {
			return errors.New("未知调度不携带成功时钟")
		}
	} else {
		at, e := time.Parse(time.RFC3339Nano, f.WorkerCheckedAt)
		if e != nil || at.After(now.Add(time.Minute)) || (f.WorkerState != "stale" && now.Sub(at) > 15*time.Second) {
			return errors.New("切流调度时钟不可核对")
		}
	}
	seen := map[string]bool{}
	for _, r := range f.Records {
		at, e := time.Parse(time.RFC3339, r.CreatedAt)
		if !ValidID(r.ID) || !ValidID(r.EntryID) || seen[r.ID] || (r.State != "pending" && r.State != "committed" && r.State != "recovered") || e != nil || at.After(now.Add(time.Minute)) {
			return errors.New("切流事务摘要身份、状态或时钟不可核对")
		}
		seen[r.ID] = true
	}
	return nil
}
func (s *Store) migrateLoadBalanceTrafficCursors() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS load_balance_traffic_cursors(
 transaction_id TEXT PRIMARY KEY,entry_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','committed','recovered')),created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS load_balance_traffic_source(id INTEGER PRIMARY KEY CHECK(id=1),worker_state TEXT NOT NULL CHECK(worker_state IN ('unknown','clear','error','stale')),worker_sequence INTEGER NOT NULL CHECK(worker_sequence>=0 AND worker_sequence<1152921504606846976),worker_checked_at TEXT NOT NULL);
 INSERT OR IGNORE INTO schema_migrations VALUES(45,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func insertLoadBalanceTrafficNotice(ctx context.Context, tx *sql.Tx, source, sourceID, severity string) error {
	var count int
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE kind='load-balance-traffic'`).Scan(&count); e != nil {
		return e
	}
	if count >= 10000 {
		return errors.New("切流通知库存已满，原游标保留；未停用实际流量或检查")
	}
	_, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'load-balance-traffic','负载均衡切流与调度记录','请核对原事务、实际流量及调度状态',?,?,?,?)`, ID(), severity, source, sourceID, time.Now().Unix())
	return e
}
func (a *Server) collectLoadBalanceTrafficNotifications(ctx context.Context) error {
	var f LoadBalanceTrafficFeed
	if e := a.Executor.Call(ctx, "GET", "/v1/load-balance-traffic-alert-events", nil, &f); e != nil {
		return e
	}
	if e := ValidateLoadBalanceTrafficFeed(f, time.Now()); e != nil {
		return e
	}
	if !f.Available {
		return nil
	}
	tx, e := a.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var phase, clock string
	var sequence int64
	e = tx.QueryRowContext(ctx, `SELECT worker_state,worker_sequence,worker_checked_at FROM load_balance_traffic_source WHERE id=1`).Scan(&phase, &sequence, &clock)
	initial := errors.Is(e, sql.ErrNoRows)
	if e != nil && !initial {
		return e
	}
	known := map[string]LoadBalanceTrafficRecord{}
	rows, e := tx.QueryContext(ctx, `SELECT transaction_id,entry_id,state,created_at FROM load_balance_traffic_cursors`)
	if e != nil {
		return e
	}
	for rows.Next() {
		var r LoadBalanceTrafficRecord
		if e = rows.Scan(&r.ID, &r.EntryID, &r.State, &r.CreatedAt); e != nil {
			rows.Close()
			return e
		}
		known[r.ID] = r
		if len(known) > 4096 {
			rows.Close()
			return errors.New("切流永久身份库存超限")
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if initial && len(known) > 0 {
		return errors.New("切流源初始化记录缺失，未重置永久身份")
	}
	seen := map[string]bool{}
	for _, r := range f.Records {
		seen[r.ID] = true
		old, present := known[r.ID]
		if present && (old.EntryID != r.EntryID || old.CreatedAt != r.CreatedAt || old.State != "pending" && old.State != r.State) {
			return errors.New("原切流事务身份改变或完成状态回退，保留原游标")
		}
		if !present && len(known) >= 4096 {
			return errors.New("切流永久身份库存已满，保留全部原记录")
		}
		if !present || old.State != r.State {
			// Historical completed records only establish the first baseline. A
			// current pending transaction is never presented as ordinary success.
			if !initial || r.State == "pending" {
				source, severity := "app:load-balance-traffic-committed", "info"
				if r.State == "pending" {
					source, severity = "app:load-balance-traffic-pending", "critical"
				}
				if r.State == "recovered" {
					source, severity = "app:load-balance-traffic-recovered", "warning"
				}
				if e = insertLoadBalanceTrafficNotice(ctx, tx, source, Hash("load-balance-traffic:" + r.ID + ":" + r.State)[:32], severity); e != nil {
					return e
				}
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO load_balance_traffic_cursors VALUES(?,?,?,?) ON CONFLICT(transaction_id) DO UPDATE SET state=excluded.state`, r.ID, r.EntryID, r.State, r.CreatedAt)
			if e != nil {
				return e
			}
			known[r.ID] = r
		}
	}
	for id := range known {
		if !seen[id] {
			return errors.New("切流完整历史缺失，未把丢失记录解释为不存在")
		}
	}
	if initial {
		phase = "unknown"
	}
	if f.WorkerState != "unknown" {
		if clock != "" {
			old, _ := time.Parse(time.RFC3339Nano, clock)
			next, _ := time.Parse(time.RFC3339Nano, f.WorkerCheckedAt)
			if next.Before(old) {
				return errors.New("切流调度时钟回退，原记录保留")
			}
		}
		if phase != f.WorkerState && (phase != "unknown" || f.WorkerState != "clear") {
			if sequence >= (1<<60)-1 {
				return errors.New("切流调度告警序号已满")
			}
			sequence++
			severity := "critical"
			if f.WorkerState == "clear" {
				severity = "info"
			}
			if e = insertLoadBalanceTrafficNotice(ctx, tx, "app:load-balance-worker", Hash("load-balance-worker:" + strconv.FormatInt(sequence, 10))[:32], severity); e != nil {
				return e
			}
		}
		phase, clock = f.WorkerState, f.WorkerCheckedAt
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO load_balance_traffic_source VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET worker_state=excluded.worker_state,worker_sequence=excluded.worker_sequence,worker_checked_at=excluded.worker_checked_at`, phase, sequence, clock)
	if e != nil {
		return e
	}
	return tx.Commit()
}
