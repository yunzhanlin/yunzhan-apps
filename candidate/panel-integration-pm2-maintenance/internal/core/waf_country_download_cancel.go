package core

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The fixed worker uses this reason only when its download context was first
// cancelled by a complete original owner request. It is not a success receipt.
const WAFCountryDownloadCancelledMessage = "已按原账户请求取消国家数据下载；未启用防护"

// A durable request to stop ONE already issued original download. A request is
// never proof that a worker stopped or that data was not already committed.
type WAFCountryDownloadCancellation struct {
	Format                 int    `json:"format"`
	JobID                  string `json:"job_id"`
	ActorID                string `json:"actor_id"`
	PayloadSHA             string `json:"payload_sha256"`
	RequestSHA             string `json:"request_sha256"`
	RequestedAt            string `json:"requested_at"`
	AutomaticReplayAllowed bool   `json:"automatic_replay_allowed"`
}

func readCountryDownloadCancellation(ctx context.Context, db accessReader, original wafCountryOriginal) (*WAFCountryDownloadCancellation, error) {
	bad := errors.New("原国家下载取消请求缺少完整绑定，保留原状态")
	var count int
	var actor, value, stamp string
	if ctx == nil || ctx.Err() != nil || db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(CASE WHEN length(CAST(actor AS BLOB))=32 THEN actor ELSE '' END),''),coalesce(min(CASE WHEN typeof(result)='text' AND length(CAST(result AS BLOB))=129 THEN result ELSE '' END),''),coalesce(min(CASE WHEN length(CAST(created_at AS BLOB))=20 THEN created_at ELSE '' END),'') FROM audit_logs WHERE action='waf.country.cancel-download' AND target=?`, original.Job.ID).Scan(&count, &actor, &value, &stamp) != nil {
		return nil, bad
	}
	if count == 0 {
		return nil, nil
	}
	parts := strings.Split(value, ":")
	t, err := time.Parse(time.RFC3339, stamp)
	if count != 1 || actor != original.Actor || len(parts) != 2 || parts[0] != original.PayloadSHA || !validLowerSHA256(parts[1]) || err != nil || t.UTC().Format(time.RFC3339) != stamp || stamp < original.Created || original.Job.State == "cancelled" || original.Job.State == "queued" {
		return nil, bad
	}
	var dispatcher, payload, dispatched string
	if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(CASE WHEN typeof(actor)='text' AND length(CAST(actor AS BLOB))=32 THEN actor ELSE '' END),''),coalesce(min(CASE WHEN typeof(result)='text' AND length(CAST(result AS BLOB))=64 THEN result ELSE '' END),''),coalesce(min(CASE WHEN typeof(created_at)='text' AND length(CAST(created_at AS BLOB))=20 THEN created_at ELSE '' END),'') FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, original.Job.ID).Scan(&count, &dispatcher, &payload, &dispatched) != nil || count != 1 || dispatcher != original.Actor || payload != original.PayloadSHA {
		return nil, bad
	}
	d, err := time.Parse(time.RFC3339, dispatched)
	if err != nil || d.UTC().Format(time.RFC3339) != dispatched || dispatched < original.Created || dispatched > stamp {
		return nil, bad
	}
	return &WAFCountryDownloadCancellation{Format: 1, JobID: original.Job.ID, ActorID: actor, PayloadSHA: original.PayloadSHA, RequestSHA: parts[1], RequestedAt: stamp}, nil
}

// Called only after HTTP independently reads the fixed Root original and
// validates its running response, complete selection and request digest.
// Permission, original identity and the dispatch boundary are repeated in the
// transaction. No state, payload, timestamp, worker or old result is replaced.
func (s *Store) requestWAFCountryDownloadCancellation(ctx context.Context, actor, id, payloadSHA, requestSHA string, selection WAFCountryDataSelection) (WAFCountryDownloadCancellation, error) {
	var empty WAFCountryDownloadCancellation
	bad := errors.New("仅原账户已开始且尚无完整结果的同一下载可以请求取消")
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) || !ValidID(id) || !validLowerSHA256(payloadSHA) || !validLowerSHA256(requestSHA) || ValidateWAFCountryDataSelection(selection) != nil {
		return empty, bad
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return empty, err
	}
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Actor != actor || original.PayloadSHA != payloadSHA || !SameWAFCountryDataSelection(original.Selection, selection) || original.Job.State != "running" {
		return empty, bad
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_results WHERE job_id=?`, id).Scan(&count) != nil || count != 0 {
		return empty, bad
	}
	proof, err := readCountryDownloadCancellation(ctx, tx, original)
	if err != nil {
		return empty, err
	}
	if proof != nil {
		if proof.RequestSHA != requestSHA {
			return empty, bad
		}
		return *proof, tx.Commit()
	}
	var dispatcher, payload string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, id).Scan(&count, &dispatcher, &payload) != nil || count != 1 || dispatcher != actor || payload != payloadSHA {
		return empty, bad
	}
	// Acquire the write boundary before the audit append without changing the
	// original row bytes. A competing complete result must win or be refused;
	// neither observer can turn an existing terminal back into running work.
	r, err := tx.ExecContext(ctx, `UPDATE runtime_jobs SET updated_at=updated_at WHERE id=? AND state='running' AND payload=? AND NOT EXISTS(SELECT 1 FROM waf_country_results WHERE job_id=runtime_jobs.id)`, id, original.Job.Payload)
	if err != nil {
		return empty, err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return empty, bad
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.cancel-download',?,?,?)`, actor, id, payloadSHA+":"+requestSHA, Now()); err != nil {
		return empty, err
	}
	proof, err = readCountryDownloadCancellation(ctx, tx, original)
	if err != nil || proof == nil {
		return empty, bad
	}
	return *proof, tx.Commit()
}

// Read-only stop/settlement evidence, never authority to fetch data, issue a
// task or activate policy. The fixed original worker already owns its lock and
// independently verifies its sealed request/envelope/started lifetime. A later
// role revocation cannot transform this past stop request into new authority.
func (s *Store) WAFCountryDownloadCancellationNative(ctx context.Context, id, actor, payloadSHA, requestSHA string) (bool, error) {
	bad := errors.New("原国家下载取消核对身份不同")
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(id) || !ValidID(actor) || !validLowerSHA256(payloadSHA) || !validLowerSHA256(requestSHA) {
		return false, bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Job.State != "running" || original.Actor != actor || original.PayloadSHA != payloadSHA {
		return false, bad
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_results WHERE job_id=?`, id).Scan(&count) != nil || count != 0 {
		return false, bad
	}
	proof, err := readCountryDownloadCancellation(ctx, tx, original)
	if err != nil || proof != nil && proof.RequestSHA != requestSHA {
		return false, bad
	}
	return proof != nil, tx.Commit()
}
