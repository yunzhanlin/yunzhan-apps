package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const ApacheWAFVersion = "2.3.0"

// This separate identity is not published or accepted by the metadata-only
// application's install/configure APIs until native activation is verified.
const ApacheWAFNativeBodyVersion = "2.4.0"

const ApacheWAFNativeCCVersion = "2.5.0"
const ApacheWAFCCLogArchiveVersion = "2.5.1"

func ApacheWAFCCVersion(version string) bool {
	return version == ApacheWAFNativeCCVersion || version == ApacheWAFCCLogArchiveVersion
}

type ApacheWAFCCConfig struct {
	EngineJobID string `json:"engine_job_id"`
}

// Explicit identities only: future versions and aliases cannot acquire native
// module authority through a version comparison or a programme upgrade.
func ApacheWAFNativeVersion(version string) bool {
	return version == ApacheWAFNativeBodyVersion || ApacheWAFCCVersion(version)
}

func DefaultApacheWAFConfig() WAFConfig {
	cfg := DefaultWAFConfig()
	cfg.Policy.CCEnabled = false
	return cfg
}

func DecodeApacheWAFConfig(raw map[string]any) (WAFConfig, error) {
	return decodeApacheWAFConfig(raw, false, false, true)
}

// A native candidate and its recovery oracle share the same closed policy
// decoder. Keeping this separate prevents a Core upgrade from silently giving
// an installed 2.3 metadata-only application new capabilities or receipts.
func DecodeApacheWAFNativeBodyConfig(raw map[string]any) (WAFConfig, error) {
	return decodeApacheWAFConfig(raw, true, false, true)
}

func DecodeApacheWAFNativeCCConfig(raw map[string]any) (WAFConfig, error) {
	return decodeApacheWAFConfig(raw, true, true, true)
}

// Core can validate a configure/preview shape before Root reads the exact
// current installation and inherits an omitted unchanged engine reference.
// This never authorizes installation, preview success or native activation.
func decodeApacheWAFNativeCCDraft(raw map[string]any) (WAFConfig, error) {
	return decodeApacheWAFConfig(raw, true, true, false)
}

func decodeApacheWAFConfig(raw map[string]any, nativeBody, nativeCC, requireCCReference bool) (WAFConfig, error) {
	if len(raw) == 0 {
		return DefaultApacheWAFConfig(), nil
	}
	if _, exists := raw["country"]; exists {
		return WAFConfig{}, errors.New("Apache 不接受 Nginx 专用地域策略；未忽略字段或宣称生效")
	}
	full, err := json.Marshal(raw)
	if err != nil || len(full) > 128<<10 {
		return WAFConfig{}, errors.New("Apache WAF 配置超过 128 KiB 或格式无效")
	}
	var cc *ApacheWAFCCConfig
	if value, exists := raw["apache_cc"]; exists {
		if !nativeCC || raw["policy"] == nil {
			return WAFConfig{}, errors.New("Apache 原生 CC 需要签名2.5.0及完整 policy，旧版不能获得该能力")
		}
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > 256 || bytes.Equal(encoded, []byte("null")) {
			return WAFConfig{}, errors.New("Apache CC 引擎引用格式无效")
		}
		var input ApacheWAFCCConfig
		d := json.NewDecoder(bytes.NewReader(encoded))
		d.DisallowUnknownFields()
		if d.Decode(&input) != nil || !ValidID(input.EngineJobID) {
			return WAFConfig{}, errors.New("Apache CC 引擎必须引用明确核验的本机构建任务")
		}
		cc = &input
		copy := make(map[string]any, len(raw))
		for k, v := range raw {
			if k != "apache_cc" {
				copy[k] = v
			}
		}
		raw = copy
	}
	if _, present := raw["policy"]; !present {
		if _, explicit := raw["trusted_proxy"]; explicit {
			return WAFConfig{}, errors.New("Apache 可信代理策略需要完整 policy 和当前修订号")
		}
		copy := make(map[string]any, len(raw)+1)
		for k, v := range raw {
			copy[k] = v
		}
		copy["policy"] = WAFSettings(DefaultApacheWAFConfig())["policy"]
		raw = copy
	}
	cfg, err := DecodeWAFConfig(raw)
	if err != nil {
		return cfg, err
	}
	cfg.ApacheCC = cc
	if cfg.Body != nil && !nativeBody {
		return cfg, errors.New("Apache 尚未实现原生请求体引擎；不能保存 Nginx 请求体策略冒充生效")
	}
	if err := ValidateApacheWAFTrustedProxy(cfg.TrustedProxy); err != nil {
		return cfg, err
	}
	if cfg.BodyLogRotation != nil || cfg.BodyLogRetention != nil {
		return cfg, errors.New("Apache 不接受 Nginx 请求体日志轮转或保留期策略")
	}
	if !nativeCC && (cfg.Policy.CCEnabled || len(cfg.Policy.CCRules) != 0) {
		return cfg, errors.New("Apache 元数据防护不提供 CC 限速；请关闭 CC 并通过 Nginx 入口配置限速")
	}
	for _, site := range cfg.Policy.Sites {
		if !nativeCC && (site.CCEnabled != nil && *site.CCEnabled || site.Rate != 0 || site.Burst != 0) {
			return cfg, errors.New("Apache 站点策略不接受独立 CC 速率或容量")
		}
	}
	if nativeCC {
		needed := cfg.Policy.CCEnabled || len(cfg.Policy.CCRules) != 0
		for _, site := range cfg.Policy.Sites {
			needed = needed || site.CCEnabled != nil && *site.CCEnabled || site.Rate != 0 || site.Burst != 0
		}
		if needed && requireCCReference && cfg.ApacheCC == nil {
			return cfg, errors.New("Apache CC 策略需要明确选择已核验的本机原生限流引擎")
		}
	}
	return cfg, nil
}

// mod_remoteip walks the address chain right-to-left. Do not offer Nginx's
// non-recursive or single-address modes while actually applying other semantics.
func ValidateApacheWAFTrustedProxy(v *WAFTrustedProxyConfig) error {
	if err := ValidateWAFTrustedProxy(v); err != nil {
		return err
	}
	if v != nil && v.Enabled && (v.Header != "X-Forwarded-For" || !v.Recursive) {
		return errors.New("Apache 可信代理仅支持 X-Forwarded-For 从右向左核对地址链；必须启用递归，不冒充 Nginx 的末尾地址或 X-Real-IP 模式")
	}
	return nil
}

func (s *Store) validateApacheWAFSites(cfg WAFConfig) error {
	for _, id := range WAFScopedSites(cfg) {
		site, err := s.Site(id)
		if err != nil || site.Status != "running" || DefaultSiteSettings(site.Settings).WebServer != "apache" {
			return errors.New("Apache 防护策略只支持正在运行的 Apache 受管网站")
		}
	}
	return nil
}

func (a *Server) apacheWAFWorkspaceRoutes(m *http.ServeMux) {
	a.apacheNumericLogRoutes(m)
	a.apacheCCArchiveRoutes(m)
	a.apacheBodyEngineRoutes(m)
	a.apacheBodyReportRoutes(m)
	a.apacheWAFHistoryRoutes(m)
	for _, operation := range []string{"config", "report"} {
		m.HandleFunc("GET /api/software/apache-waf/"+operation, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			path := "/v1/software/apache-waf/" + operation
			if operation == "report" {
				w.Header().Set("Cache-Control", "no-store")
				query, err := WAFReportQuery(r.URL.Query(), time.Now())
				if err != nil {
					fail(w, 400, err.Error())
					return
				}
				query.Del("site_domain")
				path += "?" + query.Encode()
			}
			var out any
			if err := a.Executor.Call(r.Context(), "GET", path, nil, &out); err != nil {
				fail(w, 503, err.Error())
				return
			}
			send(w, 200, out)
		}))
	}
	m.HandleFunc("POST /api/software/apache-waf/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Settings map[string]any `json:"settings"`
		}
		if !decode(w, r, &in) {
			return
		}
		// Shape validation does not authorize native activation: the executor
		// preview rechecks the exact installed version and sealed engine.
		cfg, err := decodeApacheWAFNativeCCDraft(in.Settings)
		if err == nil {
			err = a.Store.validateApacheWAFSites(cfg)
		}
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		var out any
		if err = a.Executor.Call(r.Context(), "POST", "/v1/software/apache-waf/preview", WAFSettings(cfg), &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/apache-waf/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		rows, err := a.Store.DB.QueryContext(r.Context(), `SELECT id,kind,state,error,created_at FROM runtime_jobs WHERE target_id='apache-waf' ORDER BY created_at DESC,id DESC LIMIT 50`)
		if err != nil {
			fail(w, 500, "读取操作记录失败")
			return
		}
		defer rows.Close()
		entries := []map[string]any{}
		for rows.Next() {
			var id, kind, state, message, at string
			if err = rows.Scan(&id, &kind, &state, &message, &at); err != nil {
				fail(w, 500, "读取操作记录失败")
				return
			}
			entries = append(entries, map[string]any{"id": id, "kind": kind, "state": state, "error": message, "created_at": at})
		}
		if rows.Err() != nil {
			fail(w, 500, "读取操作记录失败")
			return
		}
		send(w, 200, map[string]any{"entries": entries})
	}))
}
