package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Rotation is an explicit opt-in, separate from engine and site enablement.
// It never prunes archives or touches Nginx access/error or metadata WAF logs.
type WAFBodyLogRotationConfig struct {
	Enabled       bool `json:"enabled"`
	RotateMiB     int  `json:"rotate_mib"`
	MaxAgeMinutes int  `json:"max_age_minutes"`
}

func DefaultWAFBodyLogRotation() WAFBodyLogRotationConfig {
	return WAFBodyLogRotationConfig{RotateMiB: 16, MaxAgeMinutes: 60}
}

func ValidateWAFBodyLogRotation(v *WAFBodyLogRotationConfig) error {
	if v == nil {
		return nil
	}
	if v.RotateMiB < 1 || v.RotateMiB > 28 || v.MaxAgeMinutes < 10 || v.MaxAgeMinutes > 1440 {
		return errors.New("请求体元数据自动轮转阈值为 1–28 MiB，窗口为 10–1440 分钟；不会自动删除快照")
	}
	return nil
}

func ValidateWAFBodyLogRotationSource(v WAFConfig) error {
	if err := ValidateWAFBodyLogRetention(v.BodyLogRetention); err != nil {
		return err
	}
	if v.BodyLogRetention != nil && v.BodyLogRetention.Enabled && (v.Body == nil || !ValidID(v.Body.EngineJobID)) {
		return errors.New("自动快照清理需要明确选择本机原生请求体引擎；不会自动构建或启用防护")
	}
	if err := ValidateWAFBodyLogRotation(v.BodyLogRotation); err != nil {
		return err
	}
	if v.BodyLogRotation != nil && v.BodyLogRotation.Enabled && (v.Body == nil || !ValidID(v.Body.EngineJobID)) {
		return errors.New("自动轮转需要已明确选择的本机原生请求体引擎；不自动构建或启用网站防护")
	}
	return nil
}

type WAFBodyLogRotationRetainRequest struct {
	SHA256       string `json:"sha256"`
	Acknowledged bool   `json:"acknowledge_unknown_rotation_not_repeated"`
}

// The digest-bound acknowledgement has exactly two explicit, non-null
// fields. Reject duplicate names rather than silently accept the last value.
func (v *WAFBodyLogRotationRetainRequest) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("自动轮转核对请求必须是对象")
	}
	seen := map[string]bool{}
	var out WAFBodyLogRotationRetainRequest
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("自动轮转核对不接受重复字段")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("自动轮转核对不接受 null 或不完整值")
		}
		switch name {
		case "sha256":
			if err := json.Unmarshal(raw, &out.SHA256); err != nil {
				return err
			}
		case "acknowledge_unknown_rotation_not_repeated":
			if err := json.Unmarshal(raw, &out.Acknowledged); err != nil {
				return err
			}
		default:
			return errors.New("自动轮转核对包含未知字段")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 {
		return errors.New("自动轮转核对字段不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("自动轮转核对有额外内容")
	}
	*v = out
	return nil
}

func (v WAFBodyLogRotationRetainRequest) Valid() bool {
	return v.Acknowledged && len(v.SHA256) == 64 && strings.Trim(v.SHA256, "0123456789abcdef") == ""
}
