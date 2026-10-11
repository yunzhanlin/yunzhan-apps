package core

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// Only opaque entry identity and threshold transitions leave the executor.
// No domain, node address, health path, TLS material or response body is sent.
type LoadBalanceAlertTransition struct {
	Sequence int64  `json:"sequence"`
	From     string `json:"from"`
	To       string `json:"to"`
	Time     string `json:"time"`
}
type LoadBalanceAlertEntry struct {
	ID          string                       `json:"id"`
	Revision    int64                        `json:"revision"`
	Sequence    int64                        `json:"sequence"`
	CheckedAt   string                       `json:"checked_at"`
	Transitions []LoadBalanceAlertTransition `json:"transitions"`
}
type LoadBalanceAlertFeed struct {
	SchemaVersion int                     `json:"schema_version"`
	Available     bool                    `json:"available"`
	Entries       []LoadBalanceAlertEntry `json:"entries"`
}

func (s *Store) migrateLoadBalanceAlertCursors() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS load_balance_notification_cursors(
 entry_id TEXT PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>0 AND revision<1152921504606846976),
 sequence INTEGER NOT NULL CHECK(sequence>=0 AND sequence<1152921504606846976));
 INSERT OR IGNORE INTO schema_migrations VALUES(44,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if err != nil {
		return err
	}
	return s.migrateLoadBalanceTrafficCursors()
}
func ValidateLoadBalanceAlertFeed(feed LoadBalanceAlertFeed, now time.Time) error {
	if feed.SchemaVersion != 1 || feed.Entries == nil || len(feed.Entries) > 8 || (!feed.Available && len(feed.Entries) != 0) {
		return errors.New("负载均衡告警源格式或完整库存不可核对")
	}
	seen := map[string]bool{}
	for _, entry := range feed.Entries {
		at, err := time.Parse(time.RFC3339Nano, entry.CheckedAt)
		if !ValidID(entry.ID) || seen[entry.ID] || entry.Revision < 1 || entry.Revision >= 1<<60 || entry.Sequence < 0 || entry.Sequence >= 1<<60 || entry.Transitions == nil || len(entry.Transitions) > 32 || err != nil || at.After(now.Add(time.Minute)) {
			return errors.New("负载均衡告警入口身份或有界历史无效")
		}
		seen[entry.ID] = true
		last := int64(0)
		for _, event := range entry.Transitions {
			t, e := time.Parse(time.RFC3339Nano, event.Time)
			fromOK := event.From == "unknown" || event.From == "healthy" || event.From == "unhealthy"
			if event.Sequence <= last || (last != 0 && event.Sequence != last+1) || event.Sequence > entry.Sequence || !fromOK || (event.To != "healthy" && event.To != "unhealthy") || event.From == event.To || e != nil || t.After(at) {
				return errors.New("负载均衡告警状态转换不可核对")
			}
			last = event.Sequence
		}
		if last != entry.Sequence {
			return errors.New("负载均衡告警源末尾序号缺失")
		}
	}
	return nil
}
func loadBalanceAlertID(entry LoadBalanceAlertEntry, sequence int64) string {
	return Hash("load-balance-health:" + entry.ID + ":" + strconv.FormatInt(entry.Revision, 10) + ":" + strconv.FormatInt(sequence, 10))[:32]
}

func insertLoadBalanceNotification(ctx context.Context, tx *sql.Tx, source, sourceID, severity string, at int64) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE kind='load-balance'`).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return errors.New("负载均衡通知库存已满，原事件游标保留；请处理通知，未暂停实际健康检查")
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'load-balance','负载均衡健康变化','请核对应用 HTTP 检查、事件缺口和实际流量记录',?,?,?,?)`, ID(), severity, source, sourceID, at)
	return err
}

func (a *Server) collectLoadBalanceNotifications(ctx context.Context) error {
	var feed LoadBalanceAlertFeed
	if err := a.Executor.Call(ctx, "GET", "/v1/load-balance-alert-events", nil, &feed); err != nil {
		return err
	}
	if err := ValidateLoadBalanceAlertFeed(feed, time.Now()); err != nil {
		return err
	}
	if !feed.Available {
		return nil
	}
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, entry := range feed.Entries {
		var revision, sequence int64
		err = tx.QueryRowContext(ctx, `SELECT revision,sequence FROM load_balance_notification_cursors WHERE entry_id=?`, entry.ID).Scan(&revision, &sequence)
		initial := errors.Is(err, sql.ErrNoRows)
		if err != nil && !initial {
			return err
		}
		if !initial && (revision > entry.Revision || (revision == entry.Revision && sequence > entry.Sequence)) {
			return errors.New("负载均衡告警源或配置修订回退；原游标保留")
		}
		// First observation and a new configuration revision establish a baseline.
		// Never backfill earlier health records or reuse another entry's cursor.
		if initial || revision != entry.Revision {
			if initial {
				var count int
				if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM load_balance_notification_cursors`).Scan(&count); err != nil {
					return err
				}
				if count >= 4096 {
					return errors.New("负载均衡告警身份库存已满；保留原游标，需人工归档核对")
				}
			}
		} else {
			first := entry.Sequence + 1
			if len(entry.Transitions) > 0 {
				first = entry.Transitions[0].Sequence
			}
			if entry.Sequence > sequence && first > sequence+1 {
				gap := loadBalanceAlertID(entry, sequence) + ":gap:" + strconv.FormatInt(first, 10)
				err = insertLoadBalanceNotification(ctx, tx, "app:load-balance-gap", gap, "critical", time.Now().Unix())
				if err != nil {
					return err
				}
			}
			for _, event := range entry.Transitions {
				if event.Sequence <= sequence {
					continue
				}
				at, _ := time.Parse(time.RFC3339Nano, event.Time)
				severity := "info"
				if event.To == "unhealthy" {
					severity = "critical"
				}
				err = insertLoadBalanceNotification(ctx, tx, "app:load-balance-health", loadBalanceAlertID(entry, event.Sequence), severity, at.Unix())
				if err != nil {
					return err
				}
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO load_balance_notification_cursors VALUES(?,?,?) ON CONFLICT(entry_id) DO UPDATE SET revision=excluded.revision,sequence=excluded.sequence`, entry.ID, entry.Revision, entry.Sequence)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
