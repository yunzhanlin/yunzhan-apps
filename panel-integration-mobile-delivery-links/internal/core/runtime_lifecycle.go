package core

import (
	"database/sql"
	"errors"
	"local/panel/internal/runtimecatalog"
	"net/http"
)

var lifecycleKinds = map[string]string{"retire": "retire_runtime", "restore": "restore_runtime", "purge": "purge_runtime_copy"}

func lifecycleAction(kind string) string {
	for action, value := range lifecycleKinds {
		if value == kind {
			return action
		}
	}
	return ""
}
func (s *Store) migrateRuntimeLifecycle() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=5`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`ALTER TABLE runtime_installations ADD COLUMN status TEXT NOT NULL DEFAULT 'installed';
 CREATE TRIGGER runtime_mysql_insert_guard BEFORE INSERT ON mysql_servers
 WHEN NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=NEW.release_id AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.release_id AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention'))
 BEGIN SELECT RAISE(ABORT,'运行环境未就绪或正在变更'); END;
 CREATE TRIGGER runtime_php_insert_guard BEFORE INSERT ON jobs
 WHEN NEW.kind IN ('create_site','switch_php') AND COALESCE(json_extract(NEW.payload,'$.release_id'),'')!='' AND (NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=json_extract(NEW.payload,'$.release_id') AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=json_extract(NEW.payload,'$.release_id') AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention')))
 BEGIN SELECT RAISE(ABORT,'运行环境未就绪或正在变更'); END;
 CREATE TRIGGER runtime_php_retry_guard BEFORE UPDATE OF state ON jobs
 WHEN NEW.state='queued' AND NEW.kind IN ('create_site','switch_php') AND COALESCE(json_extract(NEW.payload,'$.release_id'),'')!='' AND (NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=json_extract(NEW.payload,'$.release_id') AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=json_extract(NEW.payload,'$.release_id') AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention')))
 BEGIN SELECT RAISE(ABORT,'运行环境未就绪或正在变更'); END;
 CREATE TRIGGER runtime_nginx_insert_guard BEFORE INSERT ON runtime_jobs
 WHEN NEW.kind='switch_nginx' AND (NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=NEW.target_id AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.target_id AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention')))
 BEGIN SELECT RAISE(ABORT,'运行环境未就绪或正在变更'); END;
 CREATE TRIGGER runtime_nginx_retry_guard BEFORE UPDATE OF state ON runtime_jobs
 WHEN NEW.state='queued' AND NEW.kind='switch_nginx' AND (NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=NEW.target_id AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.target_id AND id!=NEW.id AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention')))
 BEGIN SELECT RAISE(ABORT,'运行环境未就绪或正在变更'); END;
 CREATE TRIGGER runtime_uncertain_insert_guard BEFORE INSERT ON runtime_jobs
 WHEN EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.target_id AND kind IN ('retire_runtime','restore_runtime','purge_runtime_copy') AND state='needs_attention')
 BEGIN SELECT RAISE(ABORT,'请先重试并核对未完成的运行环境任务'); END;
 CREATE TRIGGER runtime_uncertain_retry_guard BEFORE UPDATE OF state ON runtime_jobs
 WHEN NEW.state='queued' AND EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.target_id AND id!=NEW.id AND kind IN ('retire_runtime','restore_runtime','purge_runtime_copy') AND state='needs_attention')
 BEGIN SELECT RAISE(ABORT,'请先重试并核对未完成的运行环境任务'); END;
 INSERT INTO schema_migrations VALUES(5,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) QueueRuntimeLifecycle(release, action, key, actor string) (string, error) {
	kind := lifecycleKinds[action]
	if kind == "" {
		return "", errors.New("生命周期操作无效")
	}
	releaseInfo, ok := runtimecatalog.Find(release)
	if !ok {
		return "", errors.New("只管理面板自行安装的精确版本，系统 Nginx 不可卸载")
	}
	if releaseInfo.Family == "docker" {
		return "", errors.New("Docker 是宿主机软件；请先移除容器与项目，再通过系统维护流程卸载")
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效幂等键")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var id, target, oldKind string
	e = tx.QueryRow(`SELECT id,target_id,kind FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id, &target, &oldKind)
	if e == nil {
		if target != release || oldKind != kind {
			return "", errors.New("幂等键已被不同请求使用")
		}
		return id, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	var status string
	if e = tx.QueryRow(`SELECT status FROM runtime_installations WHERE id=?`, release).Scan(&status); e != nil {
		return "", errors.New("该版本没有安装记录")
	}
	if action == "retire" && status != "installed" {
		return "", errors.New("该版本当前不在安装目录中")
	}
	if action == "restore" && status != "quarantined" {
		return "", errors.New("该版本没有待恢复的安装记录")
	}
	if action == "retire" {
		refs, e := queryRuntimeReferences(tx, release)
		if e != nil {
			return "", e
		}
		if len(refs) > 0 {
			return "", errors.New("版本仍被站点、实例、待执行任务或全局入口引用，不能卸载")
		}
	}
	id = ID()
	if _, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?)`, id, release, kind, key, Now(), Now()); e != nil {
		return "", errors.New("该版本已有进行中的任务")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'queued',?)`, actor, "runtime."+action, release, Now()); e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func finishRuntimeLifecycle(tx *sql.Tx, j Job) error {
	switch j.Kind {
	case "retire_runtime":
		_, e := tx.Exec(`UPDATE runtime_installations SET status='quarantined' WHERE id=?`, j.TargetID)
		return e
	case "restore_runtime":
		_, e := tx.Exec(`UPDATE runtime_installations SET status='installed',detected_at=? WHERE id=?`, Now(), j.TargetID)
		return e
	case "purge_runtime_copy":
		_, e := tx.Exec(`UPDATE runtime_installations SET status='removed' WHERE id=? AND status='quarantined'`, j.TargetID)
		return e
	}
	return nil
}
func (a *Server) runtimeLifecycleRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/runtimes/{id}/lifecycle/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmVersion string `json:"confirm_version"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.ConfirmVersion != r.PathValue("id") {
			fail(w, 400, "请确认操作的精确版本")
			return
		}
		job, e := a.Store.QueueRuntimeLifecycle(r.PathValue("id"), r.PathValue("action"), r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
}
