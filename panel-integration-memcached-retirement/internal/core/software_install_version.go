package core

import (
	"database/sql"
	"encoding/json"
	"errors"
)

func softwareRegistryAppID(target string) string {
	switch target {
	case "mobile-pwa":
		return "mobile"
	case "intrusion-prevention":
		return "anti-intrusion"
	}
	return target
}

type softwareInstallRowQueryer interface {
	wafApplyRowQueryer
	accessReader
}

// Resolve only the execution envelope, never rewrite the immutable original
// payload, request, pending row, receipt or failure. Older signed queues lost
// the version field; their permanent exact binding survives pending consumption
// and is sufficient to recover the selected package identity read-only.
func softwareInstallExecutionVersion(q softwareInstallRowQueryer, j Job, requested string) (string, error) {
	bad := errors.New("原软件安装版本、签名请求或任务内容不能核对；未调用执行器或改写原记录")
	if !ValidID(j.ID) || j.Kind != "software_install" || SoftwareImplementationVersion(j.TargetID) == "" {
		return "", bad
	}
	var target, kind, payload, key string
	if q.QueryRow(`SELECT target_id,kind,payload,idempotency_key FROM runtime_jobs WHERE id=?`, j.ID).Scan(&target, &kind, &payload, &key) != nil || target != j.TargetID || kind != j.Kind || payload != j.Payload {
		return "", bad
	}
	var in struct {
		Settings map[string]any `json:"settings"`
		Version  string         `json:"version"`
	}
	if len(payload) > wafApplyPayloadMax || !wafInventoryJSONShape([]byte(payload), []string{"settings", "version"}) || json.Unmarshal([]byte(payload), &in) != nil || in.Version != requested {
		return "", bad
	}
	var count int
	if q.QueryRow(`SELECT count(*) FROM app_registry_install_requests WHERE job_id=? OR runtime_job_id=? OR idempotency_key=?`, j.ID, j.ID, key).Scan(&count) != nil {
		return "", bad
	}
	if count == 0 {
		// The legacy unbound direct interface remains legacy. It cannot borrow
		// the independently signed native identities by naming a new version.
		if j.TargetID == "mobile-pwa" && requested == NativeMobileAppVersion || j.TargetID == "apache-waf" && requested == ApacheWAFNativeBodyVersion {
			return "", bad
		}
		if requested != "" && ValidateSoftwareInstallVersion(j.TargetID, requested) != nil {
			return "", bad
		}
		return requested, nil
	}
	if count != 1 || ensureRegistryRequestOpen(q, key) != nil {
		return "", bad
	}
	var actor, app, requestHash, version, digest, provider, scope, boundTarget, job, boundKey, payloadHash string
	var runtimeJob sql.NullString
	if q.QueryRow(`SELECT actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id,runtime_job_id,idempotency_key,job_payload_sha256 FROM app_registry_install_requests WHERE job_id=?`, j.ID).Scan(&actor, &app, &requestHash, &version, &digest, &provider, &scope, &boundTarget, &job, &runtimeJob, &boundKey, &payloadHash) != nil ||
		!ValidID(actor) || app != softwareRegistryAppID(j.TargetID) || !registryDigestValid(requestHash) || !registryDigestValid(digest) || provider != "panel-module" || scope != j.TargetID || boundTarget != j.TargetID || job != j.ID || !runtimeJob.Valid || runtimeJob.String != j.ID || boundKey != key || payloadHash != registryInstallDigest([]byte(payload)) ||
		validateRegistryUpdateRequest(app, actor, key, registryUpdateInput{version, digest}) != nil || ValidateSoftwareInstallVersion(j.TargetID, version) != nil || requested != "" && requested != version {
		return "", bad
	}
	if j.TargetID == "mobile-pwa" && version == NativeMobileAppVersion {
		access, err := readUserAccess(q, actor)
		if err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes"}, access.MenuIDs) {
			return "", bad
		}
	}
	return version, nil
}

// A non-nil callback or a version label is not signed authority. Inspect the
// exact registry row after that callback within the SAME queue transaction.
// Replays validate the original but never recreate consumed pending rows.
func mobileNativeQueueBinding(q softwareInstallRowQueryer, action, key, job, username, payload string) error {
	bad := errors.New("移动端1.3.2需要原签名版本、摘要、账户和任务绑定；未提交或重新采用")
	var actor, app, version, digest, provider, scope, boundJob string
	table := "app_registry_install_requests"
	if action == "update" {
		table = "app_registry_update_requests"
	} else if action != "install" {
		return bad
	}
	if ensureRegistryRequestOpen(q, key) != nil || q.QueryRow("SELECT actor_id,app_id,version,sha256,provider,scope,job_id FROM "+table+" WHERE idempotency_key=?", key).Scan(&actor, &app, &version, &digest, &provider, &scope, &boundJob) != nil || !ValidID(actor) || app != "mobile" || version != NativeMobileAppVersion || !registryDigestValid(digest) || provider != "panel-module" || scope != "mobile-pwa" || boundJob != job {
		return bad
	}
	var actualUser string
	if q.QueryRow(`SELECT username FROM users WHERE id=?`, actor).Scan(&actualUser) != nil || actualUser != username {
		return bad
	}
	access, err := readUserAccess(q, actor)
	if err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes"}, access.MenuIDs) {
		return bad
	}
	var target, kind, original, originalKey string
	if q.QueryRow(`SELECT target_id,kind,payload,idempotency_key FROM runtime_jobs WHERE id=?`, job).Scan(&target, &kind, &original, &originalKey) != nil || target != "mobile-pwa" || kind != "software_"+action || original != payload || originalKey != key {
		return bad
	}
	if action == "install" {
		resolved, err := softwareInstallExecutionVersion(q, Job{ID: job, TargetID: target, Kind: kind, Payload: original}, version)
		if err != nil || resolved != version {
			return bad
		}
	} else if payload != `{"settings":null,"version":"`+NativeMobileAppVersion+`"}` {
		return bad
	}
	return nil
}

// Recheck a retained native update at consumption too: an install payload
// cannot be borrowed as an update, and revoked current access is not restored.
func mobileNativeExecutionBinding(q softwareInstallRowQueryer, j Job) error {
	bad := errors.New("移动端原生更新的原签名任务或当前授权不可核对；未调用执行器")
	if j.TargetID != "mobile-pwa" || j.Kind != "software_update" || !ValidID(j.ID) {
		return bad
	}
	var key, username string
	if q.QueryRow(`SELECT j.idempotency_key,u.username FROM runtime_jobs j JOIN app_registry_update_requests r ON r.job_id=j.id JOIN users u ON u.id=r.actor_id WHERE j.id=? AND j.target_id=? AND j.kind=? AND j.payload=?`, j.ID, j.TargetID, j.Kind, j.Payload).Scan(&key, &username) != nil {
		return bad
	}
	return mobileNativeQueueBinding(q, "update", key, j.ID, username, j.Payload)
}
