package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var errOutboundSourceBlocked = errors.New("部分日报推送来源待核对，原事件已隔离保留；其他有效告警仍可入队")

const outboundSourceBlockFields = "CASE WHEN length(CAST(id AS BLOB))=32 THEN id ELSE NULL END,CASE WHEN length(CAST(channel_id AS BLOB))=32 THEN channel_id ELSE NULL END,channel_revision,CASE WHEN length(CAST(event_id AS BLOB))=32 THEN event_id ELSE NULL END,sequence,CASE WHEN length(CAST(kind AS BLOB))<=32 THEN kind ELSE NULL END,CASE WHEN length(CAST(severity AS BLOB))<=16 THEN severity ELSE NULL END,event_created_at,CASE WHEN length(CAST(source_id AS BLOB))<=128 THEN source_id ELSE NULL END,CASE WHEN length(CAST(state AS BLOB))<=16 THEN state ELSE NULL END,created_at,resolved_at"

type outboundSourceBlock struct {
	ID, ChannelID, EventID, Kind, Severity, SourceID, State   string
	Revision, Sequence, EventCreatedAt, CreatedAt, ResolvedAt int64
}
type outboundSourceScanner interface{ Scan(...any) error }

func readOutboundSourceBlock(row outboundSourceScanner) (outboundSourceBlock, error) {
	var b outboundSourceBlock
	err := row.Scan(&b.ID, &b.ChannelID, &b.Revision, &b.EventID, &b.Sequence, &b.Kind, &b.Severity, &b.EventCreatedAt, &b.SourceID, &b.State, &b.CreatedAt, &b.ResolvedAt)
	if err != nil {
		return b, err
	}
	if !ValidID(b.ID) || !ValidID(b.ChannelID) || !ValidID(b.EventID) || b.Revision < 1 || b.Sequence < 1 || b.Kind != "daily" || len(b.Severity) > 16 || len(b.SourceID) > 128 || b.CreatedAt < 1 || b.EventCreatedAt < 1 || (b.State != "blocked" && b.State != "resolved") || (b.State == "blocked" && b.ResolvedAt != 0) || (b.State == "resolved" && b.ResolvedAt < 1) {
		return b, errors.New("隔离来源记录无法核对；保留原记录")
	}
	return b, nil
}
func (b outboundSourceBlock) sha() string {
	data, _ := json.Marshal([]any{b.ID, b.ChannelID, b.Revision, b.EventID, b.Sequence, b.Kind, b.Severity, b.EventCreatedAt, b.SourceID, b.CreatedAt})
	return Hash(string(data))
}
func (b outboundSourceBlock) public() map[string]any {
	day := ""
	if validDailyReportDay(b.SourceID) {
		day = b.SourceID
	}
	message := "原日报来源待核对；未作为正常摘要发送，原隔离身份保留"
	if b.State == "resolved" {
		message = "来源已核对并入队；不等于接收端已接收，原隔离身份保留"
	}
	return map[string]any{"id": b.ID, "event_id": b.EventID, "state": "source_" + b.State, "attempts": 0, "http_status": 0, "error": message, "created_at": b.CreatedAt, "completed_at": b.ResolvedAt, "day": day, "source_sha": b.sha(), "channel_revision": b.Revision}
}
func insertOutboundSourceBlock(ctx context.Context, tx *sql.Tx, c NotificationChannel, n Notification, sequence int64, sourceID string) error {
	var total, active int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM notification_deliveries)+(SELECT count(*) FROM notification_source_blocks), (SELECT count(*) FROM notification_source_blocks WHERE channel_id=? AND state='blocked')`, c.ID).Scan(&total, &active); err != nil {
		return err
	}
	if total >= 10000 || active >= 1000 {
		return errors.New("推送或来源隔离容量已满；原事件和游标保留")
	}
	if !ValidID(n.ID) || n.Kind != "daily" || n.CreatedAt < 1 || len(n.Severity) > 16 || len(sourceID) > 128 || sequence < 1 {
		return errors.New("原隔离事件身份无法核对")
	}
	b := outboundSourceBlock{ID: ID(), ChannelID: c.ID, Revision: c.Revision, EventID: n.ID, Sequence: sequence, Kind: n.Kind, Severity: n.Severity, EventCreatedAt: n.CreatedAt, SourceID: sourceID, State: "blocked", CreatedAt: time.Now().Unix()}
	_, err := tx.ExecContext(ctx, `INSERT INTO notification_source_blocks(id,channel_id,channel_revision,event_id,sequence,kind,severity,event_created_at,source_id,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,'blocked',?)`, b.ID, b.ChannelID, b.Revision, b.EventID, b.Sequence, b.Kind, b.Severity, b.EventCreatedAt, b.SourceID, b.CreatedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('outbound-worker','notification.source.block',?,'retained',?)`, b.ID, Now())
	return err
}
func (s *Store) OutboundSourceBlocks(ctx context.Context, channel string) ([]map[string]any, int, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_source_blocks WHERE channel_id=?`, channel).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total > 10000 {
		return nil, 0, errors.New("原隔离库存超出容量；未返回不完整健康结果")
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+outboundSourceBlockFields+` FROM notification_source_blocks WHERE channel_id=? ORDER BY CASE state WHEN 'blocked' THEN 0 ELSE 1 END,created_at DESC,id LIMIT 100`, channel)
	if err != nil {
		return nil, 0, err
	}
	out := []map[string]any{}
	for rows.Next() {
		b, e := readOutboundSourceBlock(rows)
		if e != nil {
			rows.Close()
			return nil, 0, e
		}
		out = append(out, b.public())
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}
func (a *Server) reconcileOutboundSource(ctx context.Context, actor identity, channel, id, sha string, revision int64) (map[string]any, error) {
	if !ValidID(channel) || !ValidID(id) || !validLowerSHA256(sha) || revision < 1 {
		return nil, errors.New("请核对原通道修订与完整来源摘要")
	}
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	access, err := readUserAccessContext(ctx, tx, actor.ID)
	if err != nil || access.Role != "admin" || !containsMenu(access.MenuIDs, "panel-access") {
		return nil, errors.New("当前账户授权无法核对")
	}
	var current int64
	var enabled bool
	var kindsRaw string
	if err = tx.QueryRowContext(ctx, `SELECT revision,enabled,CASE WHEN length(CAST(kinds AS BLOB))<=1024 THEN kinds ELSE NULL END FROM notification_channels WHERE id=?`, channel).Scan(&current, &enabled, &kindsRaw); err != nil {
		return nil, errors.New("原通道无法核对")
	}
	var kinds []string
	if current != revision || !enabled || json.Unmarshal([]byte(kindsRaw), &kinds) != nil || !containsMenu(kinds, "daily") {
		return nil, errors.New("原通道修订已变化或未启用日报；未补发旧事件")
	}
	b, err := readOutboundSourceBlock(tx.QueryRowContext(ctx, "SELECT "+outboundSourceBlockFields+` FROM notification_source_blocks WHERE id=? AND channel_id=?`, id, channel))
	if err != nil || b.sha() != sha || b.Revision != revision {
		return nil, errors.New("隔离来源身份或原通道版本已变化")
	}
	if !validDailyReportDay(b.SourceID) {
		return nil, errors.New("原事件没有可核对的日报日期；隔离证据保留")
	}
	if b.State == "resolved" {
		var delivery string
		if err = tx.QueryRowContext(ctx, `SELECT id FROM notification_deliveries WHERE channel_id=? AND event_id=? AND channel_revision=?`, channel, b.EventID, revision).Scan(&delivery); err != nil {
			return nil, errors.New("原核对结果已无法完整读取；不重新创建推送")
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "event_id": b.EventID, "state": "resolved", "delivery_id": delivery, "already_resolved": true}, nil
	}
	day, record, err := readDailyReportRecord(ctx, tx, b.SourceID)
	if err != nil {
		return nil, errors.New("原日报仍无法核对；没有发送、删除或替换原记录")
	}
	summary, err := outboundDailyReportSummary(day, record)
	if err != nil {
		return nil, errors.New("原日报摘要仍无法核对")
	}
	message := safeOutboundMessage(Notification{ID: b.EventID, Kind: b.Kind, Severity: b.Severity, CreatedAt: b.EventCreatedAt})
	message.Report = &summary
	if _, err = tx.ExecContext(ctx, `UPDATE notification_source_blocks SET state='resolved',resolved_at=? WHERE id=? AND state='blocked'`, time.Now().Unix(), id); err != nil {
		return nil, err
	}
	if err = insertOutbound(tx, channel, revision, message); err != nil {
		return nil, err
	}
	var delivery, payload string
	var originalRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT id,payload,channel_revision FROM notification_deliveries WHERE channel_id=? AND event_id=?`, channel, b.EventID).Scan(&delivery, &payload, &originalRevision); err != nil {
		return nil, err
	}
	canonical, _ := json.Marshal(message)
	if originalRevision != revision || payload != string(canonical) {
		return nil, errors.New("原推送身份已有不一致记录；未据此认定入队")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'notification.source.reconcile',?,'queued',?)`, actor.Username, id, Now()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "event_id": b.EventID, "state": "resolved", "delivery_id": delivery, "already_resolved": false}, nil
}
