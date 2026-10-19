package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const memcachedClosureLimit = 4096
const memcachedClosureTable = `CREATE TABLE IF NOT EXISTS memcached_update_closures(request_id TEXT PRIMARY KEY NOT NULL,actor_id TEXT NOT NULL,project_id TEXT NOT NULL,input_record TEXT NOT NULL,created_at TEXT NOT NULL,closure_sha256 TEXT NOT NULL,CHECK(length(request_id)=32 AND length(actor_id)=32 AND length(project_id)=32 AND length(input_record) BETWEEN 1 AND 512 AND length(closure_sha256)=64))`

type memcachedUpdateClosure struct {
	Format    int                  `json:"format"`
	RequestID string               `json:"request_id"`
	ActorID   string               `json:"actor_id"`
	ProjectID string               `json:"project_id"`
	Input     MemcachedUpdateInput `json:"input"`
	CreatedAt string               `json:"created_at"`
}

func memcachedClosureSchema(ctx context.Context, db accessReader) error {
	var count int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_update_closures'`).Scan(&count) != nil || count != 2 {
		return errMemcachedUpdateStore
	}
	for _, object := range []struct{ kind, name, text string }{
		{"table", "memcached_update_closures", strings.Replace(memcachedClosureTable, " IF NOT EXISTS", "", 1)},
		{"index", "sqlite_autoindex_memcached_update_closures_1", ""},
	} {
		var kind, table, definition string
		if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(type),''),coalesce(min(tbl_name),''),coalesce(min(sql),'') FROM sqlite_master WHERE name=?`, object.name).Scan(&count, &kind, &table, &definition) != nil || count != 1 || kind != object.kind || table != "memcached_update_closures" || definition != object.text {
			return errMemcachedUpdateStore
		}
	}
	return nil
}

func migrateMemcachedClosures(tx *sql.Tx) error {
	var count int
	if tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_update_closures'`).Scan(&count) != nil {
		return errMemcachedUpdateStore
	}
	if count == 0 {
		var audits int
		if tx.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app.memcached.close'`).Scan(&audits) != nil || audits != 0 {
			return errMemcachedUpdateStore
		}
		if _, err := tx.Exec(memcachedClosureTable); err != nil {
			return err
		}
	}
	return memcachedClosureSchema(context.Background(), tx)
}

// This is SELECT-only, including when the Root worker checks an original
// reservation. A missing/tampered closure schema or orphan audit is uncertainty,
// not permission to dispatch an old late request under a new identity.
func readMemcachedClosure(ctx context.Context, db accessReader, key string) (memcachedUpdateClosure, bool, error) {
	var out memcachedUpdateClosure
	if !ValidID(key) || memcachedClosureSchema(ctx, db) != nil {
		return out, false, errMemcachedUpdateStore
	}
	var raw, digest string
	var size int
	err := db.QueryRowContext(ctx, `SELECT request_id,actor_id,project_id,substr(CAST(input_record AS BLOB),1,513),length(CAST(input_record AS BLOB)),created_at,closure_sha256 FROM memcached_update_closures WHERE request_id=?`, key).Scan(&out.RequestID, &out.ActorID, &out.ProjectID, &raw, &size, &out.CreatedAt, &digest)
	var audits int
	var auditActor, auditSHA string
	if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='app.memcached.close' AND target=?`, key).Scan(&audits, &auditActor, &auditSHA) != nil {
		return out, false, errMemcachedUpdateStore
	}
	if errors.Is(err, sql.ErrNoRows) && audits == 0 {
		return out, false, nil
	}
	if err != nil || out.RequestID != key || !ValidID(out.ActorID) || !ValidID(out.ProjectID) || size != len(raw) || size > 512 || audits != 1 || auditActor != out.ActorID || auditSHA != digest {
		return out, false, errMemcachedUpdateStore
	}
	out.Format = 1
	input, err := DecodeMemcachedUpdateInput([]byte(raw))
	if err != nil {
		return out, false, errMemcachedUpdateStore
	}
	out.Input = input
	encoded, _ := json.Marshal(input)
	stamp, err := time.Parse(time.RFC3339, out.CreatedAt)
	if err != nil || stamp.Year() < 2026 || stamp.UTC().Format(time.RFC3339) != out.CreatedAt || string(encoded) != raw {
		return out, false, errMemcachedUpdateStore
	}
	encoded, _ = json.Marshal(out)
	if Hash(string(encoded)) != digest {
		return out, false, errMemcachedUpdateStore
	}
	var reserved int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM memcached_update_requests WHERE request_id=?`, key).Scan(&reserved) != nil || reserved != 0 {
		return out, false, errMemcachedUpdateStore
	}
	return out, true, nil
}

func closureStatus(c memcachedUpdateClosure) memcachedUpdateStatus {
	return memcachedUpdateStatus{AppID: "memcached", ProjectID: c.ProjectID, RequestID: c.RequestID, State: "closed_without_submission", StateKnown: true, ExpectedVersion: c.Input.ExpectedVersion, ExpectedSHA256: c.Input.ExpectedSHA256, Detail: "已持久化确认该原请求未入队；迟到的同编号提交也将拒绝。没有取消、删除或重发实际更新任务。"}
}

func (s *Store) memcachedClosureForActor(ctx context.Context, actor, project, key string) (memcachedUpdateClosure, bool, error) {
	var empty memcachedUpdateClosure
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, actor, "") != nil || memcachedUpdateSchema(ctx, tx) != nil {
		return empty, false, errMemcachedUpdateAuthority
	}
	closed, found, err := readMemcachedClosure(ctx, tx, key)
	if err != nil || found && (closed.ActorID != actor || closed.ProjectID != project) {
		return empty, false, errMemcachedUpdateStore
	}
	return closed, found, tx.Commit()
}

func (s *Store) closeMemcachedUpdate(ctx context.Context, actor, project, key string, input MemcachedUpdateInput) (memcachedUpdateClosure, error) {
	var empty memcachedUpdateClosure
	raw, _ := json.Marshal(input)
	if !ValidID(actor) || !ValidID(project) || !ValidID(key) {
		return empty, errMemcachedUpdateStore
	}
	if _, err := DecodeMemcachedUpdateInput(raw); err != nil {
		return empty, errMemcachedUpdateStore
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, actor, "") != nil {
		return empty, errMemcachedUpdateAuthority
	}
	if memcachedUpdateSchema(ctx, tx) != nil {
		return empty, errMemcachedUpdateStore
	}
	// A genuine reservation (even reserved/unknown with no native job yet) is
	// never canceled or released through this non-submission protocol.
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM memcached_update_requests WHERE request_id=?`, key).Scan(&count) != nil || count != 0 {
		return empty, errMemcachedUpdateStore
	}
	prior, found, err := readMemcachedClosure(ctx, tx, key)
	if err != nil {
		return empty, err
	}
	if found {
		if prior.ActorID != actor || prior.ProjectID != project || prior.Input != input {
			return empty, errMemcachedUpdateStore
		}
		return prior, tx.Commit()
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM memcached_update_closures`).Scan(&count) != nil || count >= memcachedClosureLimit {
		return empty, errMemcachedUpdateStore
	}
	closed := memcachedUpdateClosure{Format: 1, RequestID: key, ActorID: actor, ProjectID: project, Input: input, CreatedAt: Now()}
	canonical, _ := json.Marshal(closed)
	digest := Hash(string(canonical))
	if _, err = tx.ExecContext(ctx, `INSERT INTO memcached_update_closures(request_id,actor_id,project_id,input_record,created_at,closure_sha256) VALUES(?,?,?,?,?,?)`, key, actor, project, string(raw), closed.CreatedAt, digest); err != nil {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.close',?,?,?)`, actor, key, digest, closed.CreatedAt); err != nil {
		return empty, err
	}
	return closed, tx.Commit()
}

func (a *Server) memcachedUpdateCloseRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/app-registry/{id}/instances/{project}/updates/{key}/close", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.PathValue("key")
		if r.PathValue("id") != "memcached" || !ValidID(project) || !ValidID(key) || r.URL.RawQuery != "" {
			fail(w, 404, "原应用、项目或请求身份无效")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxMemcachedUpdateInputBytes+1))
		input, decodeErr := DecodeMemcachedUpdateInput(raw)
		if err != nil || decodeErr != nil {
			fail(w, 400, "必须完整核对原请求版本、摘要和原项目预检")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		closed, err := a.Store.closeMemcachedUpdate(ctx, actor.ID, project, key, input)
		if err != nil {
			if errors.Is(err, errMemcachedUpdateAuthority) {
				fail(w, 403, "关闭主机更新请求需要原账户当前完整管理员权限")
				return
			}
			fail(w, 409, "不能确认原请求未入队；保留原编号，仅核对原任务，不取消、不换号或重发")
			return
		}
		send(w, 200, closureStatus(closed))
	}))
}
