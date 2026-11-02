package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"

	"local/panel/internal/appcatalog"
)

// The callback itself is not authority. Check its exact original signed
// registry row within the SAME transaction, including on idempotent replay.
// Completed jobs may have consumed pending rows, so never recreate/adopt one.
func apacheNativeQueueBinding(tx *sql.Tx, action, key, job, actor, payload string) error {
	bad := errors.New("Apache2.4原生能力需要原签名仓库版本、摘要、账户及任务绑定；未提交或重新采用")
	if action != "install" && action != "update" {
		return bad
	}
	table := "app_registry_install_requests"
	if action == "update" {
		table = "app_registry_update_requests"
	}
	var actorID, app, version, digest, provider, scope, storedJob string
	err := tx.QueryRow("SELECT actor_id,app_id,version,sha256,provider,scope,job_id FROM "+table+" WHERE idempotency_key=?", key).Scan(&actorID, &app, &version, &digest, &provider, &scope, &storedJob)
	if err != nil || !ValidID(actorID) || app != "apache-waf" || !ApacheWAFNativeVersion(version) || provider != "panel-module" || scope != "apache-waf" || storedJob != job || len(digest) != 64 {
		return bad
	}
	for _, c := range digest {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return bad
		}
	}
	// Two supported native identities must not borrow each other's signed
	// request. Keep the exact old240 empty-version envelope readable;250 has
	// no such historical format and always requires its explicit original.
	var envelope struct {
		Settings json.RawMessage `json:"settings"`
		Version  string          `json:"version"`
	}
	d := json.NewDecoder(bytes.NewReader([]byte(payload)))
	d.DisallowUnknownFields()
	if len(payload) > wafApplyPayloadMax || d.Decode(&envelope) != nil {
		return bad
	}
	canonical, err := json.Marshal(map[string]any{"settings": envelope.Settings, "version": envelope.Version})
	if err != nil || !bytes.Equal(canonical, []byte(payload)) || action == "update" && !bytes.Equal(envelope.Settings, []byte("null")) || envelope.Version != version && !(version == ApacheWAFNativeBodyVersion && envelope.Version == "") {
		return bad
	}
	var username string
	if err = tx.QueryRow("SELECT username FROM users WHERE id=?", actorID).Scan(&username); err != nil || username != actor {
		return bad
	}
	access, err := readUserAccess(tx, actorID)
	if err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "security"}, access.MenuIDs) {
		return bad
	}
	if action == "install" {
		bound, err := wafApplySignedInstallVersion(tx, "apache-waf", actorID, key, job, payload)
		if err != nil || bound != version {
			return bad
		}
		if _, err = wafApplyOriginalSettingsForRequest("apache-waf", "software_install", payload, bound); err != nil {
			return bad
		}
	}
	return nil
}

// The native identity is an explicit signed-package opt-in. Keeping the
// default metadata implementation at2.3 prevents programme upgrades and legacy
// direct install requests from silently granting body-parser authority.
func DecodeApacheWAFVersionConfig(raw map[string]any, version string) (WAFConfig, error) {
	if version == ApacheWAFNativeCCVersion {
		return DecodeApacheWAFNativeCCConfig(raw)
	}
	if version == ApacheWAFNativeBodyVersion {
		return DecodeApacheWAFNativeBodyConfig(raw)
	}
	if comparison, valid := appcatalog.CompareVersions(version, ApacheWAFVersion); !valid || comparison > 0 {
		return WAFConfig{}, errors.New("Apache 防护版本没有对应的完整处理器，未采用配置")
	}
	return DecodeApacheWAFConfig(raw)
}

// This validates a requested payload, not an installation or a healthy engine.
// Configure is finally authorized against the executor's exact private current
// installation. An empty-version install always retains metadata-only semantics.
func apacheWAFRequestedSettings(raw map[string]any, action, version string) (WAFConfig, error) {
	if action == "configure" && version == "" {
		return decodeApacheWAFNativeCCDraft(raw)
	}
	if action == "install" && version == ApacheWAFNativeCCVersion {
		return DecodeApacheWAFNativeCCConfig(raw)
	}
	if action == "configure" && version == "" || action == "install" && version == ApacheWAFNativeBodyVersion {
		return DecodeApacheWAFNativeBodyConfig(raw)
	}
	return DecodeApacheWAFConfig(raw)
}
