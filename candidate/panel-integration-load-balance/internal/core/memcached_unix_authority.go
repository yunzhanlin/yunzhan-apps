package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"local/panel/internal/appcatalog"
)

var errMemcachedUnixAuthority = errors.New("Memcached Socket 原安装请求、管理员授权或网站状态不可核对；未提交容器变更")

func memcachedUnixReservationAuthority(ctx context.Context, tx *sql.Tx, item appcatalog.CatalogItem, actor identity, op DockerProjectRequest) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || item.ID != "memcached" || item.Version != appcatalog.MemcachedUnixVersion || item.Provider != "compose" || item.Target != "memcached-cache" || !dockerRequestDigestPattern.MatchString(item.SHA256) || op.ActorID != actor.ID || op.TemplateProfile != MemcachedUnixProfile || ValidateDockerProject(op) != nil || memcachedUpdateAuthority(ctx, tx, actor.ID, "") != nil {
		return errMemcachedUnixAuthority
	}
	if op.SiteID != "" {
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM sites WHERE id=? AND status IN('running','stopped')`, op.SiteID).Scan(&count) != nil || count != 1 {
			return errMemcachedUnixAuthority
		}
	}
	// One original install may be in flight. Reserve atomically with this
	// check, before any Root delivery; concurrent pending installs must not
	// deadlock each other's independently verified native mutation fences.
	var pending int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM app_registry_pending WHERE app_id='memcached' AND version=?`, appcatalog.MemcachedUnixVersion).Scan(&pending) != nil || pending != 0 {
		return errMemcachedUnixAuthority
	}
	if memcachedUnixControlSchema(ctx, tx) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM memcached_unix_controls WHERE state<>'completed'`).Scan(&pending) != nil || pending != 0 {
		return errMemcachedUnixAuthority
	}
	return nil
}

func registryMemcachedUnixRequest(m appcatalog.Manifest, in registryInstallInput, actor, project string) (DockerProjectRequest, error) {
	if !appcatalog.IsMemcachedUnixManifest(m) || !ValidID(actor) || !ValidID(project) || in.HostPort != 0 || len(in.Settings) > 1 {
		return DockerProjectRequest{}, errMemcachedUnixAuthority
	}
	site := ""
	for key, value := range in.Settings {
		if key != "site_id" {
			return DockerProjectRequest{}, errMemcachedUnixAuthority
		}
		v, ok := value.(string)
		if !ok || v != "" && !ValidID(v) {
			return DockerProjectRequest{}, errMemcachedUnixAuthority
		}
		site = v
	}
	raw, e := MemcachedUnixRequestCompose(project, site)
	if e != nil {
		return DockerProjectRequest{}, e
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "memcached-socket-" + project[:8]
	}
	op := DockerProjectRequest{JobID: ID(), ProjectID: project, Action: "create", Name: name, Compose: raw, TemplateID: "memcached-cache", TemplateProfile: MemcachedUnixProfile, SiteID: site, ActorID: actor}
	if e = ValidateDockerProject(op); e != nil {
		return DockerProjectRequest{}, e
	}
	return op, nil
}

// SELECT-only native admission. This is one condition, NOT a signature check,
// install receipt, enqueue permission or substitute for actual Docker/FS/peer
// verification. The original Core reservation must bind this exact payload.
// Fresh SELECT-only identity data, NOT signature or mutation authority.
// Root must compare this exact reservation/receipt digest with its independently
// verified compiled-key envelope and recheck before effects and after a pull.
type MemcachedUnixBinding struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func (s *Store) CheckMemcachedUnixInstall(ctx context.Context, op DockerProjectRequest) error {
	_, err := s.MemcachedUnixInstallBinding(ctx, op)
	return err
}

func (s *Store) MemcachedUnixInstallBinding(ctx context.Context, op DockerProjectRequest) (MemcachedUnixBinding, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || op.TemplateProfile != MemcachedUnixProfile || op.RequestSHA != "" || ValidateDockerProject(op) != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, op.ActorID, "") != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	var app, provider, scope, target, actor, version, digest, payload string
	e = tx.QueryRowContext(ctx, `SELECT app_id,provider,scope,target,actor_id,version,sha256,job_payload_sha256 FROM app_registry_install_requests WHERE job_id=?`, op.JobID).Scan(&app, &provider, &scope, &target, &actor, &version, &digest, &payload)
	raw, _ := json.Marshal(op)
	if e != nil || app != "memcached" || provider != "compose" || scope != op.ProjectID || target != op.TemplateID || actor != op.ActorID || version != appcatalog.MemcachedUnixVersion || !dockerRequestDigestPattern.MatchString(digest) || payload != registryInstallDigest(raw) {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM app_registry_pending WHERE job_id=? AND app_id='memcached' AND provider='compose' AND scope=? AND target=? AND version=? AND sha256=?`, op.JobID, op.ProjectID, op.TemplateID, version, digest).Scan(&count) != nil || count != 1 {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	if op.SiteID != "" {
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM sites WHERE id=? AND status IN('running','stopped')`, op.SiteID).Scan(&count) != nil || count != 1 {
			return MemcachedUnixBinding{}, errMemcachedUnixAuthority
		}
	}
	if ctx.Err() != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	if tx.Commit() != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	return MemcachedUnixBinding{Version: version, ManifestSHA256: digest}, nil
}

// The Root-owned original create payload, not a supplied label/project alone,
// binds the website and immutable installation. A different current full
// administrator may stop an old instance without reviving its original grant.
func (s *Store) CheckMemcachedUnixOperation(ctx context.Context, actor string, original DockerProjectRequest, action string) error {
	_, err := s.MemcachedUnixOperationBinding(ctx, actor, original, action)
	return err
}

func (s *Store) MemcachedUnixOperationBinding(ctx context.Context, actor string, original DockerProjectRequest, action string) (MemcachedUnixBinding, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) || original.TemplateProfile != MemcachedUnixProfile || original.Action != "create" || ValidateDockerProject(original) != nil || (action != "start" && action != "stop" && action != "restart" && action != "update" && action != "delete") {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, actor, "") != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	var version, digest, target string
	raw, e := json.Marshal(original)
	if e != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	if tx.QueryRowContext(ctx, `SELECT r.version,r.sha256,r.target FROM app_registry_receipts r WHERE r.app_id='memcached' AND r.scope=? AND EXISTS(SELECT 1 FROM app_registry_install_requests i WHERE i.app_id=r.app_id AND i.scope=r.scope AND i.provider='compose' AND i.version=r.version AND i.sha256=r.sha256 AND i.target=r.target AND i.job_id=? AND i.actor_id=? AND i.job_payload_sha256=?)`, original.ProjectID, original.JobID, original.ActorID, registryInstallDigest(raw)).Scan(&version, &digest, &target) != nil || version != appcatalog.MemcachedUnixVersion || target != "memcached-cache" || !dockerRequestDigestPattern.MatchString(digest) {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	if original.SiteID != "" && (action == "start" || action == "restart" || action == "update") {
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM sites WHERE id=? AND status IN('running','stopped')`, original.SiteID).Scan(&count) != nil || count != 1 {
			return MemcachedUnixBinding{}, errMemcachedUnixAuthority
		}
	}
	if ctx.Err() != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	if tx.Commit() != nil {
		return MemcachedUnixBinding{}, errMemcachedUnixAuthority
	}
	return MemcachedUnixBinding{Version: version, ManifestSHA256: digest}, nil
}
