package core

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func countryRequestDetail(ctx context.Context, db accessReader, original wafCountryOriginal) (wafCountryRequestDetail, error) {
	var empty wafCountryRequestDetail
	id := original.Job.ID
	out := wafCountryRequestDetail{ActorID: original.Actor, Request: wafCountryRequestSummary{id, original.Job.State, original.Created, original.PayloadSHA}, Selection: original.Selection, ReadOnly: true}
	if db.QueryRowContext(ctx, `SELECT error FROM runtime_jobs WHERE id=? AND typeof(error)='text' AND length(CAST(error AS BLOB))<=4096`, id).Scan(&out.Error) != nil || len(out.Error) > 4096 {
		return empty, errors.New("国家数据原任务详情无法完整读取")
	}
	if original.Job.State == "cancelled" {
		proof, err := countryCancellationProof(ctx, db, original)
		if err != nil {
			return empty, err
		}
		out.Cancellation = &proof
		return out, nil
	}
	canCancel, err := countryCanCancelBeforeDispatch(ctx, db, original)
	if err != nil {
		return empty, err
	}
	out.CanCancelBeforeDispatch = canCancel
	downloadCancellation, err := readCountryDownloadCancellation(ctx, db, original)
	if err != nil {
		return empty, err
	}
	out.DownloadCancellation = downloadCancellation
	var raw []byte
	var requestSHA, digest, state, created string
	// Keep large/corrupt data inside SQLite, not in the privileged caller's
	// heap. Missing and rejected rows are distinguished below by membership.
	err = db.QueryRowContext(ctx, `SELECT request_sha256,result_sha256,body,state,created_at FROM waf_country_results WHERE job_id=? AND typeof(body)='blob' AND length(body) BETWEEN 1 AND 32768 AND length(CAST(request_sha256 AS BLOB))=64 AND length(CAST(result_sha256 AS BLOB))=64 AND length(CAST(state AS BLOB)) BETWEEN 1 AND 32 AND length(CAST(created_at AS BLOB))=20`, id).Scan(&requestSHA, &digest, &raw, &state, &created)
	if errors.Is(err, sql.ErrNoRows) && original.Job.State != "succeeded" {
		var present int
		if db.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_results WHERE job_id=?`, id).Scan(&present) != nil || present != 0 {
			return empty, errors.New("国家数据原回执存在但其类型或容量不合法，没有当作缺失结果")
		}
		if downloadCancellation != nil && original.Job.State == "failed" {
			return empty, errors.New("已提交下载的取消请求缺少完整原执行结果，未认定停止")
		}
		return out, nil // An uncertain/pre-submission failure is NOT success.
	}
	if err != nil || !validLowerSHA256(requestSHA) || !validLowerSHA256(digest) || Hash(string(raw)) != digest || state != original.Job.State {
		return empty, errors.New("国家数据完整原始结果缺失、改变或与终态不同")
	}
	parsed, err := DecodeWAFCountryDataOperation(raw, id, original.Actor, original.Selection)
	stamp, terr := time.Parse(time.RFC3339, created)
	if err != nil || terr != nil || stamp.UTC().Format(time.RFC3339) != created || parsed.RequestSHA != requestSHA || parsed.State != state || parsed.Error != out.Error {
		return empty, errors.New("国家数据完整原回执无法与原任务核对")
	}
	if downloadCancellation != nil && downloadCancellation.RequestSHA != parsed.RequestSHA || parsed.Error == WAFCountryDownloadCancelledMessage && (downloadCancellation == nil || parsed.State != "failed" || parsed.Cache != nil) {
		return empty, errors.New("国家下载原取消请求与完整原结果不同，未认定停止")
	}
	out.Result, out.ResultSHA = &parsed, digest
	return out, nil
}

type wafCountryRequestLookup struct {
	ActorID                string                   `json:"actor_id"`
	RequestID              string                   `json:"request_id"`
	StateKnown             bool                     `json:"state_known"`
	Request                *wafCountryRequestDetail `json:"request,omitempty"`
	ReadOnly               bool                     `json:"read_only"`
	AutomaticReplayAllowed bool                     `json:"automatic_replay_allowed"`
}

// Lost-queue-response lookup is STRICTLY read-only. An unknown key is not
// proof that nothing was submitted and never grants a fresh POST/retry.
func (s *Store) readWAFCountryRequestKey(ctx context.Context, actor, key string) (wafCountryRequestLookup, error) {
	var empty wafCountryRequestLookup
	if ctx == nil || ctx.Err() != nil || !ValidID(actor) || !ValidID(key) {
		return empty, errors.New("国家数据原请求查询账户或标识无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return empty, err
	}
	out := wafCountryRequestLookup{ActorID: actor, RequestID: key, ReadOnly: true}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_requests WHERE idempotency_key=?`, key).Scan(&count) != nil || count != 0 {
			return empty, errors.New("国家数据原请求存在但其任务已损坏，未认定未提交")
		}
		return out, tx.Commit()
	}
	if err != nil {
		return empty, err
	}
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Actor != actor || original.Key != key {
		return empty, errors.New("该请求标识已绑定其他账户/应用或原记录损坏，未接管")
	}
	detail, err := countryRequestDetail(ctx, tx, original)
	if err != nil {
		return empty, err
	}
	out.StateKnown, out.Request = true, &detail
	return out, tx.Commit()
}
