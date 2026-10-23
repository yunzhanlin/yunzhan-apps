package core

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

const wafBackupArchivePendingMax = 1024 // Logical metadata limit, not disk quota.

var errWAFBackupArchivePendingConflict = errors.New("原归档结果尚未确认；须先按原标识和摘要核对，不能换成另一个请求")

type WAFBackupArchivePending struct {
	ID        string `json:"resource_id"`
	SHA       string `json:"expected_sha"`
	CreatedAt string `json:"created_at"`
}

type WAFBackupArchiveRecovery struct {
	Pending  *WAFBackupArchivePending `json:"pending"`
	ReadOnly bool                     `json:"read_only"`
}

type wafBackupArchiveQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func wafBackupArchiveRequestedDetail(in WAFBackupArchiveInput) string {
	return "digest=" + in.SHA + "; original identity; no deletion or configuration change"
}

func readWAFBackupArchivePending(ctx context.Context, q wafBackupArchiveQuerier, actorID string) (*WAFBackupArchivePending, error) {
	if !ValidID(actorID) {
		return nil, errors.New("归档请求账户身份不可核对")
	}
	var out WAFBackupArchivePending
	var action, target, detail, auditTime string
	err := q.QueryRowContext(ctx, `SELECT p.resource_id,p.sha256,p.created_at,COALESCE(a.action,''),COALESCE(a.target,''),COALESCE(a.result,''),COALESCE(a.created_at,'') FROM waf_config_backup_archive_pending p LEFT JOIN audit_logs a ON a.id=p.request_audit_id WHERE p.actor_id=?`, actorID).Scan(&out.ID, &out.SHA, &out.CreatedAt, &action, &target, &detail, &auditTime)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	in := WAFBackupArchiveInput{ID: out.ID, SHA: out.SHA, Confirm: "ARCHIVE NGINX CONFIG " + out.ID}
	created, parseErr := time.Parse(time.RFC3339, out.CreatedAt)
	if ValidateWAFBackupArchive(in) != nil || parseErr != nil || created.UTC().Format(time.RFC3339) != out.CreatedAt || action != "waf.config-backup.archive-requested" || target != in.ID || detail != wafBackupArchiveRequestedDetail(in) || auditTime != out.CreatedAt {
		return nil, errors.New("原归档请求身份或请求审计不可完整核对")
	}
	return &out, nil
}

// The original actor-bound ticket and its requested audit commit together
// BEFORE handing anything to the executor. No different input can supersede
// an unresolved ticket, and no credential, configuration body or path is kept.
func (s *Store) beginWAFBackupArchive(ctx context.Context, u identity, in WAFBackupArchiveInput) error {
	if !ValidID(u.ID) || ValidateWAFBackupArchive(in) != nil {
		return errors.New("原归档请求身份不可核对")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	access, err := readUserAccess(tx, u.ID)
	if err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "security"}, access.MenuIDs) {
		return errors.New("归档请求账户授权已变化")
	}
	pending, err := readWAFBackupArchivePending(ctx, tx, u.ID)
	if err != nil {
		return err
	}
	if pending != nil && (pending.ID != in.ID || pending.SHA != in.SHA) {
		return errWAFBackupArchivePendingConflict
	}
	if pending == nil {
		rows, err := tx.QueryContext(ctx, `SELECT actor_id FROM waf_config_backup_archive_pending LIMIT ?`, wafBackupArchivePendingMax)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			count++
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil || closeErr != nil || count >= wafBackupArchivePendingMax {
			return errors.New("待核对请求库存不可读取或已达逻辑上限；未自动删除原请求")
		}
	}
	now := Now()
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, u.Username, "waf.config-backup.archive-requested", in.ID, wafBackupArchiveRequestedDetail(in), now)
	if err != nil {
		return err
	}
	if pending == nil {
		auditID, err := result.LastInsertId()
		if err != nil || auditID < 1 {
			return errors.New("原归档请求审计身份不可保存")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO waf_config_backup_archive_pending(actor_id,resource_id,sha256,created_at,request_audit_id) VALUES(?,?,?,?,?)`, u.ID, in.ID, in.SHA, now, auditID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// The validated result audit and removal of ONLY this exact actor/ID/digest
// ticket are one transaction. An audit/commit error retains the pending ticket.
// A concurrent already-confirmed replay cannot clear a newer pending identity.
func (s *Store) finishWAFBackupArchive(ctx context.Context, u identity, in WAFBackupArchiveInput, out WAFBackupArchiveResult) error {
	if !ValidID(u.ID) || ValidateWAFBackupArchive(in) != nil || out.Snapshot.ID != in.ID || out.Snapshot.SHA != in.SHA || !out.Archived || !out.RecordsRetained || out.ConfigurationChanged {
		return errors.New("原归档确认身份不可核对")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var requested int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM audit_logs WHERE actor=? AND action='waf.config-backup.archive-requested' AND target=? AND result=? LIMIT 1`, u.Username, in.ID, wafBackupArchiveRequestedDetail(in)).Scan(&requested); err != nil || requested != 1 {
		return errors.New("原归档请求审计不可核对；不能确认结果")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, u.Username, "waf.config-backup.archive-confirmed", in.ID, "digest="+in.SHA+"; original private bytes retained; same-identity replay="+strconv.FormatBool(out.Replayed), Now()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM waf_config_backup_archive_pending WHERE actor_id=? AND resource_id=? AND sha256=?`, u.ID, in.ID, in.SHA); err != nil {
		return err
	}
	return tx.Commit()
}
