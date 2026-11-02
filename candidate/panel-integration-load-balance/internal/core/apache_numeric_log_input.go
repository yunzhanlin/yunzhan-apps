package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Closed scalar objects prevent case aliases, escaped duplicate fields, null,
// unrelated confirmations and caller path inputs at both HTTP boundaries.
func DecodeApacheNumericLogMaintenance(raw []byte, kind string) (map[string]any, error) {
	fields := map[string]string{}
	switch kind {
	case "rotate":
	case "remove":
		fields = map[string]string{"sha256": "sha", "confirm_delete": "true"}
	case "retain":
		fields = map[string]string{"index_sha256": "sha", "snapshot_sha256": "optional-sha", "snapshot_missing": "bool", "confirm_unknown": "true"}
	case "retain-stage":
		fields = map[string]string{"sha256": "sha", "confirm_unknown": "true"}
	case "automatic-retain":
		fields = map[string]string{"sha256": "sha", "confirm_unknown": "true"}
	case "automatic-configure":
		fields = map[string]string{"expected_revision": "revision", "enabled": "bool", "rotate_mib": "size", "max_age_minutes": "age"}
	default:
		return nil, errors.New("Apache 日志维护操作无效")
	}
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errors.New("Apache 日志维护请求须为4 KiB以内对象")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("Apache 日志维护请求须为独立对象")
	}
	out := map[string]any{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		typ, known := fields[name]
		if err != nil || !ok || !known {
			return nil, errors.New("Apache 日志维护字段未知或不规范")
		}
		if _, seen := out[name]; seen {
			return nil, errors.New("Apache 日志维护字段重复")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("Apache 日志维护不接受null")
		}
		if typ == "revision" || typ == "size" || typ == "age" {
			var v int64
			if json.Unmarshal(value, &v) != nil || typ == "revision" && (v < 0 || v > 1000000000) || typ == "size" && (v < 1 || v > 28) || typ == "age" && (v < 10 || v > 1440) {
				return nil, errors.New("Apache 自动轮转修订、大小或时间阈值无效")
			}
			out[name] = v
		} else if typ == "bool" || typ == "true" {
			var v bool
			if json.Unmarshal(value, &v) != nil || typ == "true" && !v {
				return nil, errors.New("Apache 日志维护需要明确布尔确认")
			}
			out[name] = v
		} else {
			var v string
			if json.Unmarshal(value, &v) != nil || v != "" && (len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "") || typ == "sha" && v == "" {
				return nil, errors.New("Apache 日志维护摘要无效")
			}
			out[name] = v
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF || len(out) != len(fields) {
		return nil, errors.New("Apache 日志维护字段缺失或含额外数据")
	}
	if kind == "retain" {
		missing := out["snapshot_missing"].(bool)
		digest := out["snapshot_sha256"].(string)
		if missing && digest != "" || !missing && digest == "" {
			return nil, errors.New("未知快照的缺失状态与摘要矛盾")
		}
	}
	return out, nil
}
