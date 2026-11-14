package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const rabbitMQMigrationRequestTable = `CREATE TABLE IF NOT EXISTS rabbitmq_migration_requests (
	request_id TEXT PRIMARY KEY NOT NULL,
	job_id TEXT NOT NULL UNIQUE,
	project_id TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	dispatch TEXT NOT NULL,
	dispatch_sha256 TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('submitted', 'cancelled-before-stop', 'original-restored', 'target-published')),
	created_at TEXT NOT NULL,
	CHECK (length(request_id)=32 AND length(job_id)=32 AND length(project_id)=32 AND length(actor_id)=32
	       AND length(dispatch) BETWEEN 1 AND 2048 AND length(dispatch_sha256)=64)
)`
const rabbitMQMigrationProjectIndex = `CREATE UNIQUE INDEX IF NOT EXISTS rabbitmq_migration_active_project ON rabbitmq_migration_requests(project_id) WHERE state='submitted'`

var errRabbitMQMigrationReservation = errors.New("无法核对 RabbitMQ 原迁移请求、操作者或项目权限")

type RabbitMQMigrationDispatch struct {
	RequestID      string                 `json:"request_id"`
	JobID          string                 `json:"job_id"`
	ProjectID      string                 `json:"project_id"`
	ActorID        string                 `json:"actor_id"`
	AccessRevision int64                  `json:"access_revision"`
	Input          RabbitMQMigrationInput `json:"input"`
	SubmittedAt    string                 `json:"submitted_at"`
}

func (d RabbitMQMigrationDispatch) valid() bool {
	_, timeErr := time.Parse(time.RFC3339, d.SubmittedAt)
	return ValidID(d.RequestID) && ValidID(d.JobID) && ValidID(d.ProjectID) && ValidID(d.ActorID) &&
		d.AccessRevision > 0 && timeErr == nil && d.Input.DowntimeAcknowledged &&
		dockerRequestDigestPattern.MatchString(d.Input.SourceSHA256) &&
		dockerRequestDigestPattern.MatchString(d.Input.TargetManifestSHA256)
}

func (s *Store) migrateRabbitMQMigrationRequests() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(rabbitMQMigrationRequestTable); err != nil {
		return err
	}
	if _, err := tx.Exec(rabbitMQMigrationProjectIndex); err != nil {
		return err
	}
	return tx.Commit()
}

func rabbitMQMigrationAdministrator(ctx context.Context, db accessReader, actor string, revision int64) (UserAccess, error) {
	access, err := readUserAccessContext(ctx, db, actor)
	if !ValidID(actor) || err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 ||
		access.Revision < 1 || revision > 0 && access.Revision != revision {
		return UserAccess{}, errRabbitMQMigrationReservation
	}
	return access, nil
}

func rabbitMQMigrationRequest(ctx context.Context, db accessReader, request string) (RabbitMQMigrationDispatch, string, bool, error) {
	var dispatch RabbitMQMigrationDispatch
	var raw []byte
	var storedHash, job, project, actor, state, submitted string
	var size int
	err := db.QueryRowContext(ctx, `SELECT job_id,project_id,actor_id,substr(CAST(dispatch AS BLOB),1,2049),
		length(CAST(dispatch AS BLOB)),dispatch_sha256,state,created_at FROM rabbitmq_migration_requests WHERE request_id=?`,
		request).Scan(&job, &project, &actor, &raw, &size, &storedHash, &state, &submitted)
	if errors.Is(err, sql.ErrNoRows) {
		return dispatch, "", false, nil
	}
	if err != nil || size < 1 || size > 2048 || size != len(raw) || Hash(string(raw)) != storedHash ||
		json.Unmarshal(raw, &dispatch) != nil || !dispatch.valid() ||
		dispatch.RequestID != request || dispatch.JobID != job || dispatch.ActorID != actor ||
		dispatch.ProjectID != project || dispatch.SubmittedAt != submitted {
		return RabbitMQMigrationDispatch{}, "", false, errRabbitMQMigrationReservation
	}
	canonical, _ := json.Marshal(dispatch)
	if !bytes.Equal(raw, canonical) {
		return RabbitMQMigrationDispatch{}, "", false, errRabbitMQMigrationReservation
	}
	switch state {
	case "submitted", "cancelled-before-stop", "original-restored", "target-published":
	default:
		return RabbitMQMigrationDispatch{}, "", false, errRabbitMQMigrationReservation
	}
	var audit int
	if db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE actor=? AND action='app.rabbitmq.migration.submit'
		AND target=? AND result=? AND created_at=?`, actor, job, storedHash, submitted).Scan(&audit) != nil || audit != 1 {
		return RabbitMQMigrationDispatch{}, "", false, errRabbitMQMigrationReservation
	}
	return dispatch, state, true, nil
}

func (s *Store) reserveRabbitMQMigration(ctx context.Context, actor, project, request string, input RabbitMQMigrationInput) (RabbitMQMigrationDispatch, bool, error) {
	var empty RabbitMQMigrationDispatch
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	access, err := rabbitMQMigrationAdministrator(ctx, tx, actor, 0)
	if err != nil {
		return empty, false, err
	}
	dispatch, _, found, err := rabbitMQMigrationRequest(ctx, tx, request)
	if err != nil {
		return empty, false, err
	}
	if found {
		if dispatch.ActorID != actor || dispatch.ProjectID != project || dispatch.Input != input {
			return empty, false, errRabbitMQMigrationReservation
		}
		return dispatch, false, tx.Commit()
	}
	dispatch = RabbitMQMigrationDispatch{RequestID: request, JobID: ID(), ProjectID: project, ActorID: actor,
		AccessRevision: access.Revision, Input: input, SubmittedAt: Now()}
	if !dispatch.valid() {
		return empty, false, errRabbitMQMigrationReservation
	}
	raw, _ := json.Marshal(dispatch)
	digest := Hash(string(raw))
	_, err = tx.ExecContext(ctx, `INSERT INTO rabbitmq_migration_requests(request_id,job_id,project_id,actor_id,dispatch,
		dispatch_sha256,state,created_at) VALUES(?,?,?,?,?,?,'submitted',?)`, request, dispatch.JobID, project, actor, string(raw), digest, dispatch.SubmittedAt)
	if err != nil {
		return empty, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at)
		VALUES(?,'app.rabbitmq.migration.submit',?,?,?)`, actor, dispatch.JobID, digest, dispatch.SubmittedAt)
	if err != nil {
		return empty, false, err
	}
	return dispatch, true, tx.Commit()
}

// Executed against the installed Core database by the independent root
// executor before accepting or entering the original job.
func (s *Store) VerifyRabbitMQMigrationDispatch(ctx context.Context, expected RabbitMQMigrationDispatch) error {
	if !expected.valid() {
		return errRabbitMQMigrationReservation
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actual, state, found, err := rabbitMQMigrationRequest(ctx, tx, expected.RequestID)
	if err != nil || !found || actual != expected || state != "submitted" {
		return errRabbitMQMigrationReservation
	}
	if _, err := rabbitMQMigrationAdministrator(ctx, tx, expected.ActorID, expected.AccessRevision); err != nil {
		return err
	}
	return tx.Commit()
}

// Look up the exact reservation that the systemd unit received by immutable job
// identity. Authorization of an interrupted rollback is handled separately.
func (s *Store) ReadRabbitMQMigrationDispatch(ctx context.Context, job string) (RabbitMQMigrationDispatch, error) {
	var request string
	if !ValidID(job) || s.DB.QueryRowContext(ctx, "SELECT request_id FROM rabbitmq_migration_requests WHERE job_id=?", job).Scan(&request) != nil || !ValidID(request) {
		return RabbitMQMigrationDispatch{}, errRabbitMQMigrationReservation
	}
	actual, state, found, err := rabbitMQMigrationRequest(ctx, s.DB, request)
	if err != nil || !found || actual.JobID != job || state != "submitted" {
		return RabbitMQMigrationDispatch{}, errRabbitMQMigrationReservation
	}
	return actual, nil
}

func (s *Store) finishRabbitMQMigration(ctx context.Context, d RabbitMQMigrationDispatch, status RabbitMQMigrationStatus) error {
	if !status.matches(d) {
		return errRabbitMQMigrationReservation
	}
	switch status.Phase {
	case "cancelled-before-stop", "original-restored", "target-published":
	default:
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	saved, state, found, err := rabbitMQMigrationRequest(ctx, tx, d.RequestID)
	if err != nil || !found || saved != d || state != "submitted" && state != status.Phase {
		return errRabbitMQMigrationReservation
	}
	if state != "submitted" {
		return tx.Commit()
	}
	now := Now()
	if status.Phase == "target-published" {
		_, err = tx.ExecContext(ctx, `INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)
			VALUES('rabbitmq',?,?,?,'rabbitmq-440',?) ON CONFLICT(app_id,scope) DO UPDATE SET
			version=excluded.version,sha256=excluded.sha256,target=excluded.target,updated_at=excluded.updated_at`,
			d.ProjectID, rabbitMQ440AppVersion, d.Input.TargetManifestSHA256, now)
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE rabbitmq_migration_requests SET state=? WHERE request_id=? AND state='submitted'", status.Phase, d.RequestID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.rabbitmq.migration.result',?,?,?)`,
		d.ActorID, d.JobID, status.Phase, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}
