package core

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"local/panel/internal/runtimecatalog"
	"net/http"
)

type ExtensionJobPayload struct {
	ExtensionID string `json:"extension_id"`
}
type ExtensionInstallation struct {
	ReleaseID    string `json:"release_id"`
	ExtensionID  string `json:"extension_id"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	ABI          string `json:"abi"`
	ModuleSHA    string `json:"module_sha256"`
	InstalledAt  string `json:"installed_at"`
}

func (s *Store) migratePHPExtensions() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=6`).Scan(&n); e != nil {
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
	_, e = tx.Exec(`ALTER TABLE runtime_jobs ADD COLUMN payload TEXT NOT NULL DEFAULT '{}';
 CREATE TABLE php_extensions(release_id TEXT NOT NULL REFERENCES runtime_installations(id),extension_id TEXT NOT NULL,version TEXT NOT NULL,architecture TEXT NOT NULL,abi TEXT NOT NULL,module_sha TEXT NOT NULL,installed_at TEXT NOT NULL,PRIMARY KEY(release_id,extension_id));
 CREATE TRIGGER php_extension_install_guard BEFORE INSERT ON runtime_jobs
 WHEN NEW.kind='install_php_extension' AND (NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=NEW.target_id AND status='installed') OR EXISTS(SELECT 1 FROM runtime_jobs WHERE target_id=NEW.target_id AND kind IN ('retire_runtime','restore_runtime') AND state IN ('queued','running','needs_attention')))
 BEGIN SELECT RAISE(ABORT,'PHP 版本未就绪或正在变更'); END;
 CREATE TRIGGER php_extension_retry_guard BEFORE UPDATE OF state ON runtime_jobs
 WHEN NEW.kind='install_php_extension' AND NEW.state='queued' AND NOT EXISTS(SELECT 1 FROM runtime_installations WHERE id=NEW.target_id AND status='installed')
 BEGIN SELECT RAISE(ABORT,'PHP 版本未就绪'); END;
 INSERT INTO schema_migrations VALUES(6,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) QueuePHPExtension(release, extension, key, actor string) (string, error) {
	r, ok := runtimecatalog.Find(release)
	if !ok || r.Family != "php" {
		return "", errors.New("请选择 PHP 精确版本")
	}
	if _, ok := runtimecatalog.FindExtension(extension); !ok {
		return "", errors.New("扩展不在固定目录中")
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效幂等键")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var id, target, kind, payload string
	e = tx.QueryRow(`SELECT id,target_id,kind,payload FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id, &target, &kind, &payload)
	encoded, _ := json.Marshal(ExtensionJobPayload{ExtensionID: extension})
	if e == nil {
		if target != release || kind != "install_php_extension" || payload != string(encoded) {
			return "", errors.New("幂等键已用于其他请求")
		}
		return id, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	id = ID()
	_, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,'install_php_extension','queued',?,?,?,?)`, id, release, string(encoded), key, Now(), Now())
	if e != nil {
		return "", errors.New("PHP 版本未就绪或已有进行中的环境任务")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'php.extension.install',?,'queued',?)`, actor, release+" / "+extension, Now()); e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) RecordPHPExtension(in ExtensionInstallation) error {
	r, ok := runtimecatalog.Find(in.ReleaseID)
	if !ok || r.Family != "php" {
		return errors.New("无效 PHP 版本")
	}
	digest, digestErr := hex.DecodeString(in.ModuleSHA)
	ext, ok := runtimecatalog.FindExtension(in.ExtensionID)
	if !ok || ext.Version != in.Version || digestErr != nil || len(digest) != 32 || in.ABI == "" || (in.Architecture != "arm64" && in.Architecture != "amd64") {
		return errors.New("扩展安装证据不完整")
	}
	_, e := s.DB.Exec(`INSERT INTO php_extensions VALUES(?,?,?,?,?,?,?) ON CONFLICT(release_id,extension_id) DO UPDATE SET version=excluded.version,architecture=excluded.architecture,abi=excluded.abi,module_sha=excluded.module_sha,installed_at=excluded.installed_at`, in.ReleaseID, in.ExtensionID, in.Version, in.Architecture, in.ABI, in.ModuleSHA, in.InstalledAt)
	return e
}
func (a *Server) phpExtensionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/php/extensions/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		actual, e := a.Store.readPHPExtensions(r.Context(), a.Executor, r.PathValue("id"))
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, actual)
	}))
	m.HandleFunc("POST /api/php/extensions/{id}/install", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in ExtensionJobPayload
		if !decode(w, r, &in) {
			return
		}
		id, e := a.Store.QueuePHPExtension(r.PathValue("id"), in.ExtensionID, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))
}

type ExtensionEvidence struct {
	ReleaseID string                   `json:"release_id"`
	Status    string                   `json:"status"`
	Error     string                   `json:"error,omitempty"`
	Extension runtimecatalog.Extension `json:"extension"`
	Manifest  *struct {
		PHPRelease runtimecatalog.Release   `json:"php_release"`
		Extension  runtimecatalog.Extension `json:"extension"`
		ABI        struct {
			Version        string `json:"version"`
			Architecture   string `json:"architecture"`
			ExtensionBuild string `json:"extension_build"`
		} `json:"abi"`
		ModuleSHA   string `json:"module_sha256"`
		InstalledAt string `json:"installed_at"`
	} `json:"manifest,omitempty"`
}

func (s *Store) readPHPExtensions(ctx context.Context, e *ExecutorClient, release string) ([]ExtensionEvidence, error) {
	var out []ExtensionEvidence
	r, ok := runtimecatalog.Find(release)
	if !ok || r.Family != "php" {
		return nil, errors.New("无效 PHP 版本")
	}
	if er := e.Call(ctx, "GET", "/v1/php/extensions/"+release, nil, &out); er != nil {
		return nil, er
	}
	for _, item := range out {
		if item.Status != "installed" {
			continue
		}
		ext, ok := runtimecatalog.FindExtension(item.Extension.ID)
		if !ok || ext != item.Extension || item.ReleaseID != release || item.Manifest == nil || item.Manifest.Extension != ext || item.Manifest.PHPRelease != r || item.Manifest.ABI.Version != r.Version {
			return nil, errors.New("扩展安装清单与目录不匹配")
		}
		in := ExtensionInstallation{ReleaseID: release, ExtensionID: ext.ID, Version: ext.Version, Architecture: item.Manifest.ABI.Architecture, ABI: item.Manifest.ABI.ExtensionBuild, ModuleSHA: item.Manifest.ModuleSHA, InstalledAt: item.Manifest.InstalledAt}
		if er := s.RecordPHPExtension(in); er != nil {
			return nil, er
		}
	}
	return out, nil
}

func (s *Store) validatePHPExtensions(release string, settings *PHPSettings) error {
	if release == "" || settings == nil {
		return nil
	}
	for _, extension := range settings.Extensions {
		var n int
		if e := s.DB.QueryRow(`SELECT count(*) FROM php_extensions WHERE release_id=? AND extension_id=?`, release, extension).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return errors.New("请先为目标 PHP 版本安装所选扩展：" + release + " / " + extension)
		}
	}
	return nil
}
