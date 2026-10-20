package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"local/panel/internal/appcatalog"
	"net/http"
	"strings"
)

type registryInstallInput struct {
	Settings        map[string]any `json:"settings"`
	Name            string         `json:"name"`
	HostPort        int            `json:"host_port"`
	ExpectedVersion string         `json:"expected_version"`
	ExpectedSHA256  string         `json:"expected_sha256"`
}

type registryInstallReplay struct{ JobID, Provider, Scope, Target string }
type registryInstallBinding struct {
	registryInstallReplay
	RequestSHA256, Version, SHA256 string
}

func registryInstallRequestHash(appID, actorID, key string, in registryInstallInput) (string, error) {
	// Older clients may omit the pins; a new request still binds the actual
	// signed item. Supplied pins and all request fields remain part of identity.
	version, digest := in.ExpectedVersion, in.ExpectedSHA256
	if version == "" {
		version = "1.0.0"
	}
	if digest == "" {
		digest = strings.Repeat("0", 64)
	}
	if err := validateRegistryUpdateRequest(appID, actorID, key, registryUpdateInput{version, digest}); err != nil {
		return "", errors.New("应用安装请求标识、版本或摘要无效")
	}
	if in.Settings == nil {
		in.Settings = map[string]any{}
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 20*1024 {
		return "", errors.New("应用安装请求内容无效或过大")
	}
	return registryInstallDigest(raw), nil
}

func registryInstallDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// This is an immutable request binding, not an installation receipt. It is
// retained for failed, uncertain and successful jobs, including after receipts
// are reconciled and the remote catalog changes. Replay never requeues a job.
func (s *Store) registryInstallReplay(appID, actorID, key string, in registryInstallInput) (registryInstallReplay, bool, error) {
	requestHash, err := registryInstallRequestHash(appID, actorID, key, in)
	if err != nil {
		return registryInstallReplay{}, false, err
	}
	binding, found, err := s.registryInstallBinding(appID, actorID, key)
	if err != nil || !found {
		return binding.registryInstallReplay, found, err
	}
	if binding.RequestSHA256 != requestHash ||
		(in.ExpectedVersion != "" && in.ExpectedVersion != binding.Version) || (in.ExpectedSHA256 != "" && in.ExpectedSHA256 != binding.SHA256) {
		return registryInstallReplay{}, false, errors.New("幂等键已绑定不同用户、应用或安装内容")
	}
	return binding.registryInstallReplay, true, nil
}

// Read the immutable identity using the same job/payload checks as replay. No
// request body or credentials are needed or returned to a status reader.
func (s *Store) registryInstallBinding(appID, actorID, key string) (registryInstallBinding, bool, error) {
	var out registryInstallBinding
	if err := validateRegistryUpdateRequest(appID, actorID, key, registryUpdateInput{"1.0.0", strings.Repeat("0", 64)}); err != nil {
		return out, false, err
	}
	if err := ensureRegistryRequestOpen(s.DB, key); err != nil {
		return out, false, err
	}
	var actor, app, payloadHash string
	var runtimeJob sql.NullString
	err := s.DB.QueryRow(`SELECT actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id,runtime_job_id,job_payload_sha256 FROM app_registry_install_requests WHERE idempotency_key=?`, key).
		Scan(&actor, &app, &out.RequestSHA256, &out.Version, &out.SHA256, &out.Provider, &out.Scope, &out.Target, &out.JobID, &runtimeJob, &payloadHash)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if actor != actorID || app != appID || !ValidID(out.JobID) ||
		validateRegistryUpdateRequest(appID, actorID, key, registryUpdateInput{out.Version, out.SHA256}) != nil ||
		!registryDigestValid(out.RequestSHA256) || !registryDigestValid(payloadHash) {
		return out, false, errors.New("幂等键已绑定不同用户、应用或安装内容")
	}
	if out.Provider == "compose" {
		if runtimeJob.Valid || !ValidID(out.Scope) || !IsDockerTemplate(out.Target) {
			return out, false, errors.New("原 Compose 安装身份不一致，未重新提交")
		}
		return out, true, nil
	}
	if !runtimeJob.Valid || runtimeJob.String != out.JobID ||
		(out.Scope != out.Target && !(out.Provider == "runtime" && out.Target == "docker-auto")) {
		return out, false, errors.New("原应用安装任务身份不一致，未重新提交")
	}
	var target, kind, payload, jobKey string
	err = s.DB.QueryRow(`SELECT target_id,kind,payload,idempotency_key FROM runtime_jobs WHERE id=?`, out.JobID).Scan(&target, &kind, &payload, &jobKey)
	if err != nil || target != out.Scope || jobKey != key || registryInstallDigest([]byte(payload)) != payloadHash ||
		(out.Provider == "panel-module" && kind != "software_install") || (out.Provider == "runtime" && kind != "install_runtime") ||
		(out.Provider != "panel-module" && out.Provider != "runtime") {
		return out, false, errors.New("原应用安装任务缺失或内容不一致，未重新提交")
	}
	return out, true, nil
}

func registryDigestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func (s *Store) bindRegistryInstall(item appcatalog.CatalogItem, scope, key, actorID string, in registryInstallInput) func(*sql.Tx, string, bool) error {
	return func(tx *sql.Tx, job string, existing bool) error {
		if err := ensureRegistryRequestOpen(tx, key); err != nil {
			return err
		}
		requestHash, err := registryInstallRequestHash(item.ID, actorID, key, in)
		if err != nil {
			return err
		}
		var actor, app, oldHash, version, digest, provider, oldScope, target, oldJob string
		err = tx.QueryRow(`SELECT actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id FROM app_registry_install_requests WHERE idempotency_key=?`, key).
			Scan(&actor, &app, &oldHash, &version, &digest, &provider, &oldScope, &target, &oldJob)
		if err == nil {
			if actor != actorID || app != item.ID || oldHash != requestHash || version != item.Version || digest != item.SHA256 || provider != item.Provider || oldScope != scope || target != item.Target || oldJob != job {
				return errors.New("幂等键已绑定不同应用安装请求")
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if existing {
			return errors.New("幂等键已被未绑定的任务使用，未采用原任务")
		}
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM app_registry_install_requests`).Scan(&count); err != nil {
			return err
		}
		if count >= 100000 {
			return errors.New("应用安装请求记录达到容量上限，保留原身份，未提交")
		}
		var payload, targetID, kind, jobKey string
		if err = tx.QueryRow(`SELECT target_id,kind,payload,idempotency_key FROM runtime_jobs WHERE id=?`, job).Scan(&targetID, &kind, &payload, &jobKey); err != nil {
			return err
		}
		if targetID != scope || (scope != item.Target && !(item.Provider == "runtime" && item.Target == "docker-auto")) || jobKey != key ||
			(item.Provider == "panel-module" && kind != "software_install") || (item.Provider == "runtime" && kind != "install_runtime") ||
			(item.Provider != "panel-module" && item.Provider != "runtime") {
			return errors.New("应用安装任务内容不一致")
		}
		_, err = tx.Exec(`INSERT INTO app_registry_install_requests(idempotency_key,actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id,runtime_job_id,job_payload_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			key, actorID, item.ID, requestHash, item.Version, item.SHA256, item.Provider, scope, item.Target, job, job, registryInstallDigest([]byte(payload)), Now())
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at) VALUES(?,?,?,?,?,?,?,?)`, job, item.ID, scope, item.Version, item.SHA256, item.Target, item.Provider, Now())
		return err
	}
}

// Reserve fixed project/job IDs before the first external write. If delivery
// becomes uncertain, retry only queries that identity; it never creates a new
// project or resubmits a failed/unknown job. A new attempt needs a new key.
func (s *Store) reserveRegistryCompose(item appcatalog.CatalogItem, key string, u identity, in registryInstallInput, op DockerProjectRequest) (registryInstallReplay, bool, error) {
	var out registryInstallReplay
	requestHash, err := registryInstallRequestHash(item.ID, u.ID, key, in)
	if err != nil {
		return out, false, err
	}
	if item.Provider != "compose" || item.Target != op.TemplateID || op.Action != "create" || ValidateDockerProject(op) != nil {
		return out, false, errors.New("Compose 安装请求内容不一致")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	if err := ensureRegistryRequestOpen(tx, key); err != nil {
		return out, false, err
	}
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM app_registry_install_requests WHERE idempotency_key=?`, key).Scan(&n); err != nil {
		return out, false, err
	}
	if n != 0 {
		// The winning caller is the only one allowed to perform the POST.
		return out, false, errors.New("安装请求已被保留，请查询原任务")
	}
	if err = tx.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&n); err != nil || n != 0 {
		return out, false, errors.New("幂等键已被其他任务使用")
	}
	if err = tx.QueryRow(`SELECT count(*) FROM app_registry_install_requests`).Scan(&n); err != nil {
		return out, false, err
	}
	if n >= 100000 {
		return out, false, errors.New("应用安装请求记录达到容量上限，未提交")
	}
	raw, _ := json.Marshal(op)
	_, err = tx.Exec(`INSERT INTO app_registry_install_requests(idempotency_key,actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id,runtime_job_id,job_payload_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,NULL,?,?)`,
		key, u.ID, item.ID, requestHash, item.Version, item.SHA256, item.Provider, op.ProjectID, item.Target, op.JobID, registryInstallDigest(raw), Now())
	if err == nil {
		_, err = tx.Exec(`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at) VALUES(?,?,?,?,?,?,?,?)`, op.JobID, item.ID, op.ProjectID, item.Version, item.SHA256, item.Target, item.Provider, Now())
	}
	if err == nil {
		_, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app-registry.install',?,'reserved',?)`, u.Username, item.ID, Now())
	}
	if err != nil {
		return out, false, err
	}
	out = registryInstallReplay{op.JobID, item.Provider, op.ProjectID, item.Target}
	return out, true, tx.Commit()
}

func (a *Server) sendRegistryInstallReplay(w http.ResponseWriter, r *http.Request, prior registryInstallReplay) {
	if prior.Provider != "compose" {
		send(w, 202, map[string]string{"job_id": prior.JobID, "provider": prior.Provider, "target": prior.Scope})
		return
	}
	var result DockerJobResult
	if a.Executor == nil || a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/jobs/"+prior.JobID, nil, &result) != nil ||
		result.JobID != prior.JobID || result.ProjectID != prior.Scope || result.Kind != "compose" || !validRegistryComposeJobState(result.State) {
		send(w, 503, map[string]string{"error": "原 Compose 安装是否提交尚未确认；已保留原项目和任务标识，未重复安装，请核对 Docker 任务", "job_id": prior.JobID, "project_id": prior.Scope, "state": "needs_attention"})
		return
	}
	send(w, 202, result)
}

func validRegistryComposeJobState(state string) bool {
	return state == "queued" || state == "running" || state == "succeeded" || state == "failed" || state == "needs_attention"
}
