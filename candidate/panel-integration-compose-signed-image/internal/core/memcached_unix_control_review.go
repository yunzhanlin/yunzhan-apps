package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
)

const MaxMemcachedUnixControlReviewBytes = 4096

type MemcachedUnixControlReviewInput struct {
	ExpectedRuntimeSHA256      string `json:"expected_runtime_sha256"`
	AcknowledgeOriginalUnknown bool   `json:"acknowledge_original_unknown"`
}
type MemcachedUnixControlReviewRequest struct {
	Format     int                              `json:"format"`
	Operation  MemcachedUnixControlOperation    `json:"operation"`
	ReviewerID string                           `json:"reviewer_id"`
	Input      *MemcachedUnixControlReviewInput `json:"input,omitempty"`
}
type MemcachedUnixControlReviewView struct {
	Format          int                         `json:"format"`
	RequestID       string                      `json:"request_id"`
	ProjectID       string                      `json:"project_id"`
	OperationSHA256 string                      `json:"operation_sha256"`
	OriginalOutcome string                      `json:"original_outcome"`
	CurrentState    string                      `json:"current_state,omitempty"`
	RuntimeSHA256   string                      `json:"runtime_sha256,omitempty"`
	Observation     *MemcachedUnixControlResult `json:"observation,omitempty"`
}

func ValidateMemcachedUnixControlReviewRequest(in MemcachedUnixControlReviewRequest) error {
	if in.Format != 1 || ValidateMemcachedUnixControlOperation(in.Operation) != nil || !ValidID(in.ReviewerID) {
		return ErrMemcachedUnixControl
	}
	if in.Input != nil && (!registryDigestValid(in.Input.ExpectedRuntimeSHA256) || !in.Input.AcknowledgeOriginalUnknown) {
		return ErrMemcachedUnixControl
	}
	return nil
}
func DecodeMemcachedUnixControlReviewRequest(raw []byte) (MemcachedUnixControlReviewRequest, error) {
	var in MemcachedUnixControlReviewRequest
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixControlReviewBytes || json.Unmarshal(raw, &in) != nil || ValidateMemcachedUnixControlReviewRequest(in) != nil {
		return in, ErrMemcachedUnixControl
	}
	canonical, _ := json.Marshal(in)
	if !bytes.Equal(raw, canonical) {
		return MemcachedUnixControlReviewRequest{}, ErrMemcachedUnixControl
	}
	return in, nil
}
func ValidateMemcachedUnixControlReviewView(op MemcachedUnixControlOperation, value MemcachedUnixControlReviewView) error {
	if ValidateMemcachedUnixControlOperation(op) != nil || value.Format != 1 || value.RequestID != op.RequestID || value.ProjectID != op.ProjectID || value.OperationSHA256 != MemcachedUnixControlSHA(op) || value.OriginalOutcome != "unknown" {
		return ErrMemcachedUnixControl
	}
	if value.Observation != nil {
		if value.CurrentState != "" || value.RuntimeSHA256 != "" || value.Observation.State != "observed" || ValidateMemcachedUnixControlResult(op, *value.Observation) != nil {
			return ErrMemcachedUnixControl
		}
	} else if (value.CurrentState != "running" && value.CurrentState != "stopped" && !(op.Input.Action == "retire" && value.CurrentState == "retired")) || !registryDigestValid(value.RuntimeSHA256) {
		return ErrMemcachedUnixControl
	}
	return nil
}

// A different CURRENT full host administrator may review an old unknown after
// its issuer loses permission. This does not grant a command or adopt identity.
// Root still needs its original private run, signature, CID and real engine.
func (s *Store) MemcachedUnixControlReviewBinding(ctx context.Context, reviewer, key string) (MemcachedUnixControlOperation, error) {
	var empty MemcachedUnixControlOperation
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(reviewer) || !ValidID(key) {
		return empty, ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, reviewer, "") != nil {
		return empty, ErrMemcachedUnixControl
	}
	row, found, err := readMemcachedUnixControl(ctx, tx, key)
	if err != nil || !found {
		return empty, ErrMemcachedUnixControl
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return row.Operation, nil
}
func (s *Store) CheckMemcachedUnixControlReview(ctx context.Context, in MemcachedUnixControlReviewRequest, otherQueues bool) error {
	if ValidateMemcachedUnixControlReviewRequest(in) != nil {
		return ErrMemcachedUnixControl
	}
	original, err := s.MemcachedUnixControlReviewBinding(ctx, in.ReviewerID, in.Operation.RequestID)
	if err != nil || original != in.Operation {
		return ErrMemcachedUnixControl
	}
	if otherQueues {
		var count int
		if s.DB.QueryRowContext(ctx, "SELECT count(*)FROM memcached_unix_controls WHERE state<>'completed' AND request_id<>?", in.Operation.RequestID).Scan(&count) != nil || count != 0 || s.CheckMemcachedUnixInstallUpgrade(ctx) != nil || s.CheckMemcachedUpdateUpgrade(ctx) != nil {
			return ErrMemcachedUnixControl
		}
	}
	original, err = s.MemcachedUnixControlReviewBinding(ctx, in.ReviewerID, in.Operation.RequestID)
	if err != nil || original != in.Operation {
		return ErrMemcachedUnixControl
	}
	return nil
}

// A Root observation settles the queue separately from the unknown command.
// Current reviewer authorization is rechecked inside the same SQL transaction.
// Repeated GET/reconciliation retains one row and one review audit, never a job.
func (s *Store) finishMemcachedUnixControlReview(ctx context.Context, reviewer string, op MemcachedUnixControlOperation, result MemcachedUnixControlResult) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(reviewer) || ValidateMemcachedUnixControlResult(op, result) != nil || result.State != "observed" {
		return ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, reviewer, "") != nil {
		return ErrMemcachedUnixControl
	}
	row, found, err := readMemcachedUnixControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.Operation != op {
		return ErrMemcachedUnixControl
	}
	if row.State == "completed" {
		if row.Result == nil || *row.Result != result {
			return ErrMemcachedUnixControl
		}
		return tx.Commit()
	}
	raw, _ := json.Marshal(result)
	stamp := Now()
	changed, err := tx.ExecContext(ctx, "UPDATE memcached_unix_controls SET state='completed',result=?,updated_at=? WHERE request_id=? AND state IN('reserved','unknown')", string(raw), stamp, op.RequestID)
	if err != nil {
		return err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return ErrMemcachedUnixControl
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.unix.review',?,?,?)", reviewer, op.RequestID, string(raw), stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) finishMemcachedUnixControlReply(ctx context.Context, actor string, op MemcachedUnixControlOperation, result *MemcachedUnixControlResult) error {
	if result != nil && result.State == "observed" {
		return s.finishMemcachedUnixControlReview(ctx, actor, op, *result)
	}
	return s.finishMemcachedUnixControl(ctx, op, result)
}
