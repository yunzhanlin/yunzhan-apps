package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"local/panel/internal/runtimecatalog"
)

// RuntimeFailedInstallEvidence describes a retained failed native installation,
// never a successful runtime, retry grant, dispatch request or closure marker.
// Its private Root producer and actual stopped unit are authenticated separately.
type RuntimeFailedInstallEvidence struct {
	JobID, ReleaseID, Error string
	ExtensionID             string
	Steps                   []Step
}

// ValidateRuntimeFailedInstall is SELECT-only. Both authorities must retain the
// same original failure and every original step. Revoked users do not turn a
// completed failure into an active compiler, and this check grants no operation.
// The returned digest binds repeated reads to the entire original Core row.
func (s *Store) ValidateRuntimeFailedInstall(ctx context.Context, in RuntimeFailedInstallEvidence) (string, error) {
	bad := errors.New("运行时失败安装缺少匹配的原始双侧终态；阻止程序升级")
	r, known := runtimecatalog.Find(in.ReleaseID)
	if ctx.Err() != nil || !ValidID(in.JobID) || !known || r.Family == "docker" || in.Error == "" || len(in.Error) > 65536 || len(in.Steps) < 1 || len(in.Steps) > 128 || in.Steps[len(in.Steps)-1].Message != in.Error {
		return "", bad
	}
	kindWant, queuedAction, queuedTarget := "install_runtime", "runtime.install", in.ReleaseID
	payloadWant := ""
	// An extension failure must name the fixed extension in both the original
	// canonical queue payload and its audit target. It cannot borrow the parent
	// runtime's installation authority or the audit of another extension.
	if in.ExtensionID != "" {
		if _, ok := runtimecatalog.FindExtension(in.ExtensionID); !ok || r.Family != "php" {
			return "", bad
		}
		kindWant, queuedAction = "install_php_extension", "php.extension.install"
		queuedTarget += " / " + in.ExtensionID
		encoded, err := json.Marshal(ExtensionJobPayload{ExtensionID: in.ExtensionID})
		if err != nil {
			return "", bad
		}
		payloadWant = string(encoded)
	}
	rawSteps, err := json.Marshal(in.Steps)
	if err != nil || len(rawSteps) > 192<<10 {
		return "", bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", bad
	}
	defer tx.Rollback()
	var target, kind, state, detail, steps, payload, key, created, updated string
	if tx.QueryRowContext(ctx, `SELECT target_id,kind,state,error,steps,payload,idempotency_key,created_at,updated_at FROM runtime_jobs WHERE id=?`, in.JobID).Scan(&target, &kind, &state, &detail, &steps, &payload, &key, &created, &updated) != nil || target != in.ReleaseID || kind != kindWant || state != "failed" || detail != in.Error || steps != string(rawSteps) || len(payload) > 128<<10 || key == "" || len(key) > 128 || (in.ExtensionID != "" && payload != payloadWant) {
		return "", bad
	}
	start, e1 := time.Parse(time.RFC3339, created)
	end, e2 := time.Parse(time.RFC3339, updated)
	if e1 != nil || e2 != nil || start.UTC().Format(time.RFC3339) != created || end.UTC().Format(time.RFC3339) != updated || start.Year() < 2026 || end.Before(start) || end.After(time.Now().UTC().Add(time.Second)) {
		return "", bad
	}
	previous := start
	for _, step := range in.Steps {
		stamp, err := time.Parse(time.RFC3339, step.Time)
		if err != nil || stamp.UTC().Format(time.RFC3339) != step.Time || stamp.Before(previous) || stamp.After(end) || step.Message == "" || len(step.Message) > 65536 {
			return "", bad
		}
		previous = stamp
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM runtime_native_retry_grants WHERE job_id=? AND consumed_at IS NULL`, in.JobID).Scan(&count) != nil || count != 0 {
		return "", bad
	}
	// Existing runtime audit records use release IDs rather than job IDs. Exact
	// original timestamps and unique rows are mandatory; ambiguity stays blocked.
	var actor string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),'') FROM audit_logs WHERE action=? AND target=? AND result='queued' AND created_at=?`, queuedAction, queuedTarget, created).Scan(&count, &actor) != nil || count != 1 || actor == "" {
		return "", bad
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE actor='executor' AND action=? AND target=? AND result='failed' AND created_at=?`, kindWant, target, updated).Scan(&count) != nil || count != 1 {
		return "", bad
	}
	bound, _ := json.Marshal([]string{in.JobID, target, kind, state, detail, steps, payload, key, created, updated, actor})
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return "", bad
	}
	return Hash(string(bound)), nil
}
