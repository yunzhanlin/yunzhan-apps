package core

import (
	"errors"
	"sort"
)

type WAFBodyPolicy struct {
	Mode            string `json:"mode"`
	Paranoia        int    `json:"paranoia_level"`
	Threshold       int    `json:"inbound_threshold"`
	BodyLimitKiB    int    `json:"body_limit_kib"`
	NonFileLimitKiB int    `json:"non_file_limit_kib"`
	JSONDepth       int    `json:"json_depth"`
	ArgumentLimit   int    `json:"argument_limit"`
}

type WAFBodySitePolicy struct {
	SiteID string        `json:"site_id"`
	Policy WAFBodyPolicy `json:"policy"`
}

// Explicit per-site opt-in. An absent body policy never loads an engine or
// silently protects/enables previously unselected websites.
type WAFBodyConfig struct {
	EngineJobID string              `json:"engine_job_id"`
	Sites       []WAFBodySitePolicy `json:"sites"`
}

func DefaultWAFBodyPolicy() WAFBodyPolicy {
	return WAFBodyPolicy{"observe", 1, 5, 1024, 256, 64, 256}
}

func ValidateWAFBodyPolicy(v WAFBodyPolicy) error {
	if v.Mode != "block" && v.Mode != "observe" && v.Mode != "off" {
		return errors.New("请求体防护模式仅允许 block/observe/off")
	}
	if v.Paranoia < 1 || v.Paranoia > 4 || v.Threshold < 5 || v.Threshold > 100 {
		return errors.New("CRS 防护级别为 1–4，入站异常阈值为 5–100")
	}
	if v.BodyLimitKiB < 64 || v.BodyLimitKiB > 8192 || v.NonFileLimitKiB < 64 || v.NonFileLimitKiB > 2048 || v.NonFileLimitKiB > v.BodyLimitKiB {
		return errors.New("请求体限制为 64–8192 KiB，非文件内容为 64–2048 KiB 且不得大于请求体限制")
	}
	if v.JSONDepth < 4 || v.JSONDepth > 128 || v.ArgumentLimit < 16 || v.ArgumentLimit > 1000 {
		return errors.New("JSON 深度为 4–128，参数上限为 16–1000")
	}
	return nil
}

func validateWAFBodyConfig(v *WAFBodyConfig) error {
	if v == nil {
		return nil
	}
	if (v.EngineJobID != "" && !ValidID(v.EngineJobID)) || len(v.Sites) > 64 {
		return errors.New("WAF 引擎任务标识无效或请求体站点策略超过 64 条")
	}
	seen := map[string]bool{}
	for _, site := range v.Sites {
		if !ValidID(site.SiteID) || seen[site.SiteID] {
			return errors.New("请求体防护站点标识重复或无效")
		}
		seen[site.SiteID] = true
		if err := ValidateWAFBodyPolicy(site.Policy); err != nil {
			return err
		}
		if site.Policy.Mode != "off" && v.EngineJobID == "" {
			return errors.New("启用请求体防护必须选择已验证的本机原生引擎任务")
		}
	}
	sort.Slice(v.Sites, func(i, j int) bool { return v.Sites[i].SiteID < v.Sites[j].SiteID })
	return nil
}

// The global/site-wide off or observe switches cannot be bypassed by a body
// policy. Metadata IP/URL/UA allowlists do not silently disable body scanning.
func WAFEffectiveBodyPolicy(v WAFConfig, id string) (WAFBodyPolicy, bool) {
	if v.Body == nil {
		return WAFBodyPolicy{}, false
	}
	for _, site := range v.Body.Sites {
		if site.SiteID != id {
			continue
		}
		policy := site.Policy
		wideMode := v.Policy.Mode
		if wideMode != "off" {
			for _, p := range v.Policy.Sites {
				if p.SiteID == id && p.Mode != "" && p.Mode != "inherit" {
					if p.Mode == "off" || p.Mode == "observe" || wideMode != "observe" {
						wideMode = p.Mode
					}
					break
				}
			}
		}
		if wideMode == "off" {
			policy.Mode = "off"
		} else if wideMode == "observe" && policy.Mode == "block" {
			policy.Mode = "observe"
		}
		return policy, policy.Mode != "off"
	}
	return WAFBodyPolicy{}, false
}
