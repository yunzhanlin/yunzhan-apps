package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type NetworkIDSRuleFeedSelection struct {
	FeedID          string `json:"feed_id"`
	AppVersion      string `json:"app_version"`
	AppManifestSHA  string `json:"app_manifest_sha256"`
	RuleManifestSHA string `json:"rule_manifest_sha256"`
}

type NetworkIDSRuleFeedStatus struct {
	JobID                string                      `json:"job_id"`
	State                string                      `json:"state"`
	Selection            NetworkIDSRuleFeedSelection `json:"selection"`
	DataOnly             bool                        `json:"data_only"`
	CaptureStarted       bool                        `json:"capture_started"`
	NativeSyntaxVerified bool                        `json:"native_syntax_verified"`
	Error                string                      `json:"error,omitempty"`
	Steps                []Step                      `json:"steps"`
}

type NetworkIDSRuleFeedStored struct {
	Selection NetworkIDSRuleFeedSelection `json:"selection"`
	State     string                      `json:"state"`
	Error     string                      `json:"error,omitempty"`
}

type NetworkIDSRuleFeedInventory struct {
	StateKnown     bool                       `json:"state_known"`
	Rows           []NetworkIDSRuleFeedStored `json:"rows"`
	RetainedStages int                        `json:"retained_stages"`
	Error          string                     `json:"error,omitempty"`
}

type NetworkIDSRuleFeedAvailable struct {
	Selection NetworkIDSRuleFeedSelection `json:"selection"`
	Assets    []appcatalog.RuleFeedAsset  `json:"assets"`
	Bytes     int                         `json:"download_bytes"`
	Supported bool                        `json:"supported"`
	Detail    string                      `json:"detail,omitempty"`
}

type NetworkIDSRuleFeedPage struct {
	Source               appcatalog.LoadInfo           `json:"source"`
	Available            []NetworkIDSRuleFeedAvailable `json:"available"`
	Stored               NetworkIDSRuleFeedInventory   `json:"stored"`
	Jobs                 []Job                         `json:"jobs"`
	DataOnly             bool                          `json:"data_only"`
	CaptureStarted       bool                          `json:"capture_started"`
	NativeSyntaxVerified bool                          `json:"native_syntax_verified"`
}

var networkIDSFeedPattern = regexp.MustCompile(`^et-open-web-[0-9]{8}$`)
var networkIDSFeedSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateNetworkIDSRuleFeedSelection(in NetworkIDSRuleFeedSelection) error {
	if !networkIDSFeedPattern.MatchString(in.FeedID) || !appcatalog.ValidVersion(in.AppVersion) || len(in.AppVersion) > 64 || !networkIDSFeedSHA.MatchString(in.AppManifestSHA) || !networkIDSFeedSHA.MatchString(in.RuleManifestSHA) {
		return errors.New("规则数据选择身份、版本或摘要无效")
	}
	if _, err := time.Parse("20060102", strings.TrimPrefix(in.FeedID, "et-open-web-")); err != nil {
		return errors.New("规则数据日期无效")
	}
	return nil
}

func ValidateNetworkIDSRuleFeedManifestOn(manifest appcatalog.Manifest, platform, architecture string) error {
	if manifest.ID != "network-threat-detection" || manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || manifest.Stage != "ready" {
		return errors.New("规则数据应用处理器或阶段不符合固定契约")
	}
	if err := ValidateSoftwareUpdate(manifest.ID, manifest.Version); err != nil {
		return err
	}
	return appCompatibleOn(manifest, platform, architecture)
}

func decodeNetworkIDSRuleFeedSelection(raw []byte) (NetworkIDSRuleFeedSelection, error) {
	var out NetworkIDSRuleFeedSelection
	if len(raw) < 1 || len(raw) > 1024 {
		return out, errors.New("规则选择超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, errors.New("规则选择必须是闭合对象")
	}
	allowed := map[string]bool{"feed_id": true, "app_version": true, "app_manifest_sha256": true, "rule_manifest_sha256": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return out, errors.New("规则选择字段重复、未知或名称不规范")
		}
		seen[name] = true
		value, err := d.Token()
		if _, ok := value.(string); err != nil || !ok {
			return out, errors.New("规则选择仅接受版本和摘要字符串")
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != 4 {
		return out, errors.New("规则选择字段不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return out, errors.New("规则选择包含多余内容")
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, ValidateNetworkIDSRuleFeedSelection(out)
}

// The durable job contains only a small signed-release selection, never the
// multi-megabyte rules or a caller-supplied repository/key. Download occurs in
// the background install worker; the privileged receiver verifies it again.
func (s *Store) QueueNetworkIDSRuleFeed(in NetworkIDSRuleFeedSelection, key, actor string) (string, error) {
	if err := ValidateNetworkIDSRuleFeedSelection(in); err != nil {
		return "", err
	}
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key || actor == "" || len(actor) > 128 {
		return "", errors.New("请提供有效的幂等键")
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	id, found, err := networkIDSRuleFeedReplay(tx, in, key, actor)
	if err != nil {
		return "", err
	}
	if found {
		return id, nil
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id='network-threat-detection' AND kind='network_ids_rulefeed_install'`).Scan(&count); err != nil {
		return "", err
	}
	if count >= 64 {
		return "", errors.New("规则安装任务达到 64 份；原记录保留，未自动清理")
	}
	id = ID()
	if _, err := tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,'network-threat-detection','network_ids_rulefeed_install','queued',?,?,?,?)`, id, string(payload), key, Now(), Now()); err != nil {
		return "", errors.New("网络威胁检测已有正在执行的操作；未并行提交")
	}
	if _, err := tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'network.ids.rules.install',?,'queued-data-only',?)`, actor, id, Now()); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// Replay only observes an immutable actor/selection-bound job. A changed or
// unavailable catalog must not turn a lost reply into another install.
func networkIDSRuleFeedReplay(db interface {
	QueryRow(string, ...any) *sql.Row
}, in NetworkIDSRuleFeedSelection, key, actor string) (string, bool, error) {
	if ValidateNetworkIDSRuleFeedSelection(in) != nil || key == "" || len(key) > 128 || strings.TrimSpace(key) != key || actor == "" || len(actor) > 128 {
		return "", false, errors.New("规则安装幂等身份无效")
	}
	var id, target, kind, previous, state string
	err := db.QueryRow(`SELECT id,target_id,kind,payload,state FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id, &target, &kind, &previous, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	payload, err := json.Marshal(in)
	if err != nil || !ValidID(id) || target != "network-threat-detection" || kind != "network_ids_rulefeed_install" || previous != string(payload) || !(state == "queued" || state == "running" || state == "succeeded" || state == "failed" || state == "needs_attention") {
		return "", false, errors.New("幂等键已用于不同请求或原任务身份损坏")
	}
	var count int
	var boundActor, result sql.NullString
	if err := db.QueryRow(`SELECT count(*),min(actor),min(result) FROM audit_logs WHERE action='network.ids.rules.install' AND target=?`, id).Scan(&count, &boundActor, &result); err != nil {
		return "", false, err
	}
	if count != 1 || !boundActor.Valid || boundActor.String != actor || !result.Valid || result.String != "queued-data-only" {
		return "", false, errors.New("原规则任务的用户绑定或审计身份不能核对；未重发")
	}
	return id, true, nil
}

func (a *Server) networkIDSRuleFeedRoutes(m *http.ServeMux) {
	admin := func(w http.ResponseWriter, u identity) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "IDS 规则数据仅管理员可管理")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/network-threat-detection/rule-feeds", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		ctx, cancel := contextWithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var module struct {
			Status SoftwareAppStatus `json:"status"`
		}
		if err := a.Executor.Call(ctx, "GET", "/v1/app-modules/network-threat-detection", nil, &module); err != nil || !module.Status.Installed {
			fail(w, 409, "请先安装网络威胁检测模块")
			return
		}
		catalog, source, err := a.loadAppCatalog(15*time.Second, r)
		if err != nil {
			fail(w, 503, "规则应用目录不能验签，未展示虚假规则列表")
			return
		}
		out := NetworkIDSRuleFeedPage{Source: source, Available: []NetworkIDSRuleFeedAvailable{}, Jobs: []Job{}, DataOnly: true}
		item, ok := appcatalog.Find(catalog, "network-threat-detection")
		if !ok {
			fail(w, 409, "仓库未声明网络威胁检测应用")
			return
		}
		manifest, err := a.AppCatalog.FetchManifest(ctx, item, filepath.Join(a.appRegistryCacheDir(), "packages"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		compatibility := ValidateNetworkIDSRuleFeedManifestOn(manifest, runtimecatalog.HostPlatform(), runtime.GOARCH)
		feeds := manifest.RuleFeeds
		if manifest.RuleDataChannel != nil {
			authority, err := a.AppCatalog.FetchRuleDataAuthority(ctx, item.Version, item.SHA256, time.Now(), nil)
			if err != nil {
				fail(w, 503, "独立规则数据目录不能确认："+err.Error())
				return
			}
			feeds = []appcatalog.RuleFeed{authority.Catalog().Feed}
		}
		for _, feed := range feeds {
			row := NetworkIDSRuleFeedAvailable{Selection: NetworkIDSRuleFeedSelection{feed.ID, item.Version, item.SHA256, feed.ManifestSHA256}, Assets: feed.Assets, Supported: compatibility == nil && !source.Stale}
			for _, asset := range feed.Assets {
				row.Bytes += asset.Bytes
			}
			if compatibility != nil {
				row.Detail = compatibility.Error()
			} else if source.Stale {
				row.Detail = "目录过期，不能确认最新规则版本"
			}
			out.Available = append(out.Available, row)
		}
		if err := a.Executor.Call(ctx, "GET", "/v1/network-ids/rule-feeds", nil, &out.Stored); err != nil {
			out.Stored = NetworkIDSRuleFeedInventory{Rows: []NetworkIDSRuleFeedStored{}, Error: "本机规则数据不能独立核对"}
		}
		rows, err := a.Store.DB.Query(`SELECT id,target_id,kind,state,error,created_at,updated_at FROM runtime_jobs WHERE target_id='network-threat-detection' AND kind='network_ids_rulefeed_install' ORDER BY created_at DESC,id DESC LIMIT 16`)
		if err != nil {
			fail(w, 503, "规则任务记录读取失败")
			return
		}
		defer rows.Close()
		for rows.Next() {
			var job Job
			if err := rows.Scan(&job.ID, &job.TargetID, &job.Kind, &job.State, &job.Error, &job.CreatedAt, &job.UpdatedAt); err != nil {
				fail(w, 503, "规则任务记录不完整")
				return
			}
			out.Jobs = append(out.Jobs, job)
		}
		if err := rows.Err(); err != nil {
			fail(w, 503, "规则任务记录读取中断")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/network-threat-detection/rule-feeds/install", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		in, err := decodeNetworkIDSRuleFeedSelection(raw)
		if readErr != nil || err != nil {
			fail(w, 400, "规则选择输入重复、无效或超限")
			return
		}
		if err := ValidateNetworkIDSRuleFeedSelection(in); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if id, found, err := networkIDSRuleFeedReplay(a.Store.DB, in, r.Header.Get("Idempotency-Key"), u.ID); err != nil {
			fail(w, 409, err.Error())
			return
		} else if found {
			send(w, 202, map[string]any{"job_id": id, "replayed": true, "data_only": true, "capture_started": false, "native_syntax_verified": false})
			return
		}
		if err := ValidateSoftwareUpdate("network-threat-detection", in.AppVersion); err != nil {
			fail(w, 409, err.Error())
			return
		}
		ctx, cancel := contextWithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var module struct {
			Status SoftwareAppStatus `json:"status"`
		}
		if err := a.Executor.Call(ctx, "GET", "/v1/app-modules/network-threat-detection", nil, &module); err != nil || !module.Status.Installed {
			fail(w, 409, "请先安装网络威胁检测模块")
			return
		}
		q := r.URL.Query()
		q.Set("refresh", "1")
		r.URL.RawQuery = q.Encode()
		catalog, source, err := a.loadAppCatalog(15*time.Second, r)
		if err != nil || source.Stale {
			fail(w, 503, "不能确认仓库最新目录；未提交规则安装")
			return
		}
		item, ok := appcatalog.Find(catalog, "network-threat-detection")
		if !ok || item.Version != in.AppVersion || item.SHA256 != in.AppManifestSHA {
			fail(w, 409, "规则应用目录已变化，请刷新后重试")
			return
		}
		manifest, err := a.AppCatalog.FetchManifest(ctx, item, filepath.Join(a.appRegistryCacheDir(), "packages"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		if err := ValidateNetworkIDSRuleFeedManifestOn(manifest, runtimecatalog.HostPlatform(), runtime.GOARCH); err != nil {
			fail(w, 409, err.Error())
			return
		}
		bound := false
		if manifest.RuleDataChannel != nil {
			authority, err := a.AppCatalog.FetchRuleDataAuthority(ctx, item.Version, item.SHA256, time.Now(), nil)
			if err != nil {
				fail(w, 503, "独立规则数据目录不能确认："+err.Error())
				return
			}
			feed := authority.Catalog().Feed
			bound = feed.ID == in.FeedID && feed.ManifestSHA256 == in.RuleManifestSHA
		}
		for _, feed := range manifest.RuleFeeds {
			if feed.ID == in.FeedID && feed.ManifestSHA256 == in.RuleManifestSHA {
				bound = true
			}
		}
		if !bound {
			fail(w, 409, "规则数据不在指定的已签名应用中")
			return
		}
		id, err := a.Store.QueueNetworkIDSRuleFeed(in, r.Header.Get("Idempotency-Key"), u.ID)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]any{"job_id": id, "data_only": true, "capture_started": false, "native_syntax_verified": false})
	}))
}
